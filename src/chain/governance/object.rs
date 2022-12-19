use bitcoin_hashes::{Hash, sha256d};
use bitcoin_hashes::hex::FromHex;
use byte::BytesExt;
use byte::ctx::{Bytes, Str};
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::Zeroable;
use crate::crypto::UInt256;
use crate::crypto::primitives::utxo::UTXO;
use crate::chain::chain::Chain;
use crate::chain::governance;
use crate::chain::governance::{ObjectType, Vote};
use crate::chain::network::peer::Peer;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::wallet::account::Account;

pub struct ProposalInfo {
    pub name: Option<String>,
    pub start_epoch: Option<u64>,
    pub end_epoch: Option<u64>,
    pub r#type: Option<u32>,
    pub payment_address: Option<String>,
    pub payment_amount: Option<f64>,
    pub url: Option<String>,
}

pub struct Object {
    pub parent_hash: UInt256,
    pub revision: u32,
    pub collateral_hash: UInt256,
    pub signature: Option<&'static [u8]>,
    pub timestamp: u64,
    pub r#type: ObjectType,
    pub governance_object_hash: UInt256,
    pub chain: &'static Chain,
    pub proposal_info: ProposalInfo,
//@property (nonatomic, readonly) NSString * governanceMessage;
}

impl Object {
    fn hash_with_parent_hash(parent_hash: &UInt256, timestamp: u64, revision: u32, timestamp_data: u8, hex_data: Vec<u8>, masternode_utxo: UTXO, signature: Vec<u8>, chain: &Chain) -> UInt256 {
        let mut writer: Vec<u8> = Vec::new();
        parent_hash.enc(&mut writer);
        revision.enc(&mut writer);
        timestamp_data.enc(&mut writer);
        hex_data.enc(&mut writer);
        masternode_utxo.enc(&mut writer);
        0u8.enc(&mut writer);
        u32::MAX.enc(&mut writer);
        (signature.len() as u8).enc(&mut writer);
        signature.enc(&mut writer);
        UInt256::sha256d(&buffer)
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


    pub fn collateral_transaction_for_account(&self, account: &Account) -> &dyn ITransaction {
        account.proposal_collateral_transaction_with_data(self.proposal_info())
    }

    pub fn register_collateral_transaction(&mut self, transaction: &dyn ITransaction) {
        self.collateral_hash = transaction.tx_hash()
    }

    pub fn is_valid(&self) -> bool {
        match self.r#type {
            ObjectType::Proposal => {
                if self.proposal_info.start_epoch.is_none() {
                    return false
                }
                if self.proposal_info.end_epoch.is_none() {
                    return false;
                }
                if self.proposal_info.name.is_none() {
                    return false;
                }
                if self.proposal_info.payment_address.is_none() {
                    return false;
                }
                if self.proposal_info.payment_amount.is_none() {
                    return false;
                }
                if self.proposal_info.url.is_none() {
                    return false;
                }
                if !self.parent_hash.is_zero() {
                    return false;
                }
                if self.collateral_hash.is_zero() {
                    return false;
                }
                false

            },
            ObjectType::Trigger => true,
            _ => false
        }
    }

    pub fn init_with_message(message: &[u8], chain: &Chain) -> Option<Self> {
        let switched_to_outpoint = chain.params.protocol_version >= 70209;
        let offset = &mut 0;
        let parent_hash = message.read_with::<UInt256>(offset, byte::LE)?;
        let revision = message.read_with::<u32>(offset, byte::LE)?;
        let timestamp = message.read_with::<u64>(offset, byte::LE)?;
        let collateral_hash = message.read_with::<UInt256>(offset, byte::LE)?;
        let var_int = message.read_with::<VarInt>(offset, byte::LE)?;
        let var_int_length = var_int.0 as usize;
        //switch to outpoint in 70209

        todo!("impl")
        if switched_to_outpoint {
            // message_data is UTF
            let str = message.read_with::<&str>(offset, Str::Len(var_int_length))?;
            // let message_data: &[u8] = message.read_with(offset, Bytes::Len(var_int_length))?;

            NSMutableData *mHexData = [NSMutableData data];
            governanceMessageData = [[message stringAtOffset:offset length:&varIntLength] dataUsingEncoding:NSUTF8StringEncoding];
            [mHexData appendString:[governanceMessageData hexString]];
            hexData = [mHexData copy];

        } else {
            // message_data is HEX
            let str = message.read_with::<&str>(offset, Str::Len(var_int_length))?;
            let data = Vec::from_hex(str);

// /            let data: &[u8] = message.read_with(offset, Bytes::Len(var_int_length))?;

            //let message_data = message.read_with::<&str>(offset, Str::Len(var_int_length))?;
            let governance_message_data = Vec::from_hex(message_data).unwrap();
        }
        let object_type = message.read_with::<ObjectType>(offset, byte::LE)?;
        let masternode_utxo = message.read_with::<UTXO>(offset, byte::LE)?;
        if !switched_to_outpoint {
            let sigscript_size = message.read_with::<u8>(offset, byte::LE)?;
            let _sigscript: &[u8] = message.read_with(offset, Bytes::Len(sigscript_size as usize))?;
            let _sequence_number = message.read_with::<u32>(offset, byte::LE)?;
        }
        let message_signature_size = message.read_with::<u8>(offset, byte::LE)?;
        let message_signature: &[u8] = message.read_with(offset, Bytes::Len(message_signature_size as usize))?;




        NSUInteger length = message.length;
        NSUInteger offset = 0;
        if (length - offset < 32) return nil;
        NSData *parentHashData = [message subdataWithRange:NSMakeRange(offset, 32)];
        UInt256 parentHash = [message readUInt256AtOffset:&offset];
        if (length - offset < 4) return nil;
        uint32_t revision = [message readUInt32AtOffset:&offset];
        if (length - offset < 8) return nil;
        NSData *timestampData = [message subdataWithRange:NSMakeRange(offset, 8)];
        uint64_t timestamp = [message readUInt64AtOffset:&offset];
        if (length - offset < 32) return nil;
        UInt256 collateralHash = [message readUInt256AtOffset:&offset];
        NSNumber *varIntLength = nil;
        NSData *governanceMessageData;
        NSData *hexData;
        if (chain.protocolVersion < 70209) { //switch to outpoint in 70209
            governanceMessageData = [NSData dataFromHexString:[message stringAtOffset:offset length:&varIntLength]];
            hexData = [message subdataWithRange:NSMakeRange(offset, varIntLength.integerValue)];
        } else {
            NSMutableData *mHexData = [NSMutableData data];
            governanceMessageData = [[message stringAtOffset:offset length:&varIntLength] dataUsingEncoding:NSUTF8StringEncoding];
            [mHexData appendString:[governanceMessageData hexString]];
            hexData = [mHexData copy];
        }

        offset += [varIntLength integerValue];



        NSString *identifier = nil;
        uint64_t amount = 0;
        uint64_t startEpoch = 0;
        uint64_t endEpoch = 0;
        NSString *paymentAddress = nil;
        NSString *url = nil;

        if (governanceObjectType == DSGovernanceObjectType_Proposal) {
            NSError *jsonError = nil;


            id governanceArray = [NSJSONSerialization JSONObjectWithData:governanceMessageData options:0 error:&jsonError];
            NSDictionary *proposalDictionary = [governanceArray isKindOfClass:[NSDictionary class]] ? governanceArray : nil;
            while (!proposalDictionary) {
                if ([governanceArray count]) {
                if ([governanceArray count] > 1 && [[governanceArray objectAtIndex:0] isEqualToString:@"proposal"]) {
                proposalDictionary = [governanceArray objectAtIndex:1];
                } else if ([[governanceArray objectAtIndex:0] isKindOfClass:[NSArray class]]) {
                governanceArray = [governanceArray objectAtIndex:0];
                } else if ([[governanceArray objectAtIndex:0] isKindOfClass:[NSDictionary class]]) {
                proposalDictionary = [governanceArray objectAtIndex:0];
                } else {
                break;
                }
                } else {
                break;
                }
            }

            if (proposalDictionary) {
                identifier = proposalDictionary[@"name"];
                startEpoch = [proposalDictionary[@"start_epoch"] longLongValue];
                endEpoch = [proposalDictionary[@"end_epoch"] longLongValue];
                paymentAddress = proposalDictionary[@"payment_address"];
                amount = [[[NSDecimalNumber decimalNumberWithDecimal:[proposalDictionary[@"payment_amount"] decimalValue]] decimalNumberByMultiplyingByPowerOf10:8] unsignedLongLongValue];
                url = proposalDictionary[@"url"];
            }
        }

        UInt256 governanceObjectHash = [self hashWithParentHash:parentHashData revision:revision timeStampData:timestampData governanceMessageHexData:hexData masternodeUTXO:masternodeUTXO signature:messageSignature onChain:chain];

        DSGovernanceObject *governanceObject = [[DSGovernanceObject alloc] initWithType:governanceObjectType parentHash:parentHash revision:revision timestamp:timestamp signature:messageSignature collateralHash:collateralHash governanceObjectHash:governanceObjectHash identifier:identifier amount:amount startEpoch:startEpoch endEpoch:endEpoch paymentAddress:paymentAddress url:url onChain:chain];
        return governanceObject;

    }
}
