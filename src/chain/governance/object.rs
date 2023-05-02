use byte::BytesExt;
use byte::ctx::{Bytes, Str};
use hashes::hex::{FromHex, ToHex};
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::Zeroable;
use crate::crypto::UInt256;
use crate::crypto::UTXO;
use crate::chain::chain::Chain;
use crate::chain::governance::{ObjectType, Vote};
use crate::chain::governance::proposal::ProposalJson;
use crate::chain::network::Peer;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::wallet::account::Account;

#[derive(Debug, Default)]
pub struct Object {
    pub parent_hash: UInt256,
    pub revision: u32,
    pub collateral_hash: UInt256,
    pub signature: Option<&'static [u8]>,
    pub timestamp: u64,
    pub r#type: ObjectType,
    pub governance_object_hash: UInt256,
    pub chain: &'static Chain,
    pub proposal_info: Option<ProposalJson>,
//@property (nonatomic, readonly) NSString * governanceMessage;

    pub total_governance_vote_count: u32,
}

impl Object {
    fn hash_with_parent_hash(parent_hash: &UInt256, timestamp: u64, revision: u32, hex_data: &[u8], masternode_utxo: UTXO, signature: &[u8], chain: &Chain) -> UInt256 {
        let mut writer: Vec<u8> = Vec::new();
        parent_hash.enc(&mut writer);
        revision.enc(&mut writer);
        timestamp.enc(&mut writer);
        hex_data.to_vec().enc(&mut writer);
        masternode_utxo.enc(&mut writer);
        0u8.enc(&mut writer);
        u32::MAX.enc(&mut writer);
        (signature.len() as u8).enc(&mut writer);
        signature.to_vec().enc(&mut writer);
        UInt256::sha256d(&writer)
    }

    pub fn data_message(&self) -> Vec<u8> {
        let mut writer: Vec<u8> = Vec::new();
        self.parent_hash.enc(&mut writer);
        self.revision.enc(&mut writer);
        self.timestamp.enc(&mut writer);
        self.collateral_hash.enc(&mut writer);
        self.collateral_hash.enc(&mut writer);
        self.proposal_info().enc(&mut writer);
        self.r#type.enc(&mut writer);
        UInt256::MIN.enc(&mut writer);
        0u32.enc(&mut writer);
        0u8.enc(&mut writer);
        writer
    }



    pub fn proposal_info(&self) -> Vec<u8> {
        todo!()
        // serde_json::
        //
        // NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
        // dictionary[@"name"] = self.identifier;
        // dictionary[@"start_epoch"] = @(self.startEpoch);
        // dictionary[@"end_epoch"] = @(self.endEpoch);
        // dictionary[@"type"] = @(1);
        // dictionary[@"payment_address"] = self.paymentAddress;
        // dictionary[@"payment_amount"] = [NSDecimalNumber decimalNumberWithMantissa:self.amount exponent:-8 isNegative:FALSE];
        // dictionary[@"url"] = self.url;
        // NSArray *proposalArray = @[@[@"proposal", dictionary]];
        // NSError *error = nil;
        //     NSData *data = [NSJSONSerialization dataWithJSONObject:proposalArray options:NSJSONWritingSortedKeys error:&error];
        //     NSString *dataString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        //     dataString = [dataString stringByReplacingOccurrencesOfString:@"\\/" withString:@"/"];
        //     data = [dataString dataUsingEncoding:NSUTF8StringEncoding];
        //     return data;
    }

    pub fn peer_has_governance_vote_hashes(&self, peer: &Peer, governance_vote_hashes: Vec<UInt256>) {
        // TODO: impl processing

    }

    pub fn peer_relayed_governance_vote(&self, peer: &Peer, governance_vote: &Vote) {
        let governance_vote_hash = governance_vote.vote_hash;
        // TODO: impl processing

    }

    pub fn save(&self) {
        // TODO: impl storing
        /*[self.managedObjectContext performBlockAndWait:^{
            DSGovernanceObjectEntity *governanceObjectEntity = self.governanceObjectEntity;
            governanceObjectEntity.totalVotesCount = self.totalGovernanceVoteCount;
            [self.managedObjectContext ds_save];
        }];*/
    }


    pub fn collateral_transaction_for_account(&self, account: &mut Account) -> &dyn ITransaction {
        account.proposal_collateral_transaction_with_data(self.proposal_info()).unwrap()
    }

    pub fn register_collateral_transaction(&mut self, transaction: &dyn ITransaction) {
        self.collateral_hash = transaction.tx_hash()
    }

    pub fn is_valid(&self) -> bool {
        match self.r#type {
            ObjectType::Proposal => self.proposal_info.is_some() && self.parent_hash.is_zero() && !self.collateral_hash.is_zero(),
            ObjectType::Trigger => true,
            _ => false
        }
    }

    pub fn init_with_message(message: &[u8], chain: &Chain) -> Self {
        let switch_to_outpoint = chain.params.protocol_version < 70209;
        let offset = &mut 0;
        let parent_hash = message.read_with::<UInt256>(offset, byte::LE).unwrap();
        let revision = message.read_with::<u32>(offset, byte::LE).unwrap();
        let timestamp = message.read_with::<u64>(offset, byte::LE).unwrap();
        let collateral_hash = message.read_with::<UInt256>(offset, byte::LE).unwrap();
        let var_int = message.read_with::<VarInt>(offset, byte::LE).unwrap();
        let var_int_length = var_int.0 as usize;
        // switch to outpoint in 70209
        let str = message.read_with::<&str>(offset, Str::Len(var_int_length)).unwrap();
        // todo: check read string validity
        let (governance_message_data, hex_data) = if switch_to_outpoint {
            // message_data is UTF
            let governance_message_data = Vec::from_hex(str).unwrap();
            (governance_message_data, &message[*offset..*offset + var_int_length])
        } else {
            // message_data is HEX
            let governance_message_data = str.as_bytes();
            (governance_message_data.to_vec(), governance_message_data.to_hex().as_bytes())
        };
        let object_type = message.read_with::<ObjectType>(offset, byte::LE).unwrap();
        let masternode_utxo = message.read_with::<UTXO>(offset, byte::LE).unwrap();
        if !switch_to_outpoint {
            let sigscript_size = message.read_with::<u8>(offset, byte::LE).unwrap();
            let _sigscript: &[u8] = message.read_with(offset, Bytes::Len(sigscript_size as usize)).unwrap();
            let _sequence_number = message.read_with::<u32>(offset, byte::LE).unwrap();
        }
        let message_signature_size = message.read_with::<u8>(offset, byte::LE).unwrap();
        let message_signature: &[u8] = message.read_with(offset, Bytes::Len(message_signature_size as usize)).unwrap();
        Object {
            parent_hash,
            revision,
            collateral_hash,
            signature: Some(message_signature),
            timestamp,
            r#type: object_type,
            governance_object_hash: Self::hash_with_parent_hash(&parent_hash, timestamp, revision, hex_data, masternode_utxo, message_signature, chain),
            chain,
            proposal_info: if object_type == ObjectType::Proposal { Some(serde_json::from_slice(governance_message_data.as_slice()).unwrap()) } else { None },
            ..Default::default()
        }
    }
}
