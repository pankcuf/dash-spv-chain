use bitcoin_hashes::{Hash, sha256d};
use byte::{BytesExt, LE, TryRead};
use byte::ctx::{Bytes, Endian};
use crate::consensus::Encodable;
use crate::crypto::UInt256;
use crate::models::MasternodeEntry;
use crate::chain::chain::Chain;
use crate::chain::governance;
use crate::chain::governance::{VoteOutcome, VoteSignal};
use crate::crypto::primitives::utxo::UTXO;

pub struct Vote {
    pub object: Option<governance::Object>,
    pub masternode: Option<MasternodeEntry>,
    pub outcome: VoteOutcome,
    pub signal: VoteSignal,
    pub created_at: u64,
    pub signature: &'static [u8],
    pub parent_hash: UInt256,
    pub masternode_utxo: UTXO,
    pub vote_hash: UInt256,
    pub chain: &'static Chain
}

impl Vote {

    fn hash_with_parent_hash(parent_hash: &UInt256, timestamp: u64, signal: &VoteSignal, outcome: &VoteOutcome, masternode_utxo: &UTXO) -> UInt256 {
        let mut writer: Vec<u8> = Vec::new();
        masternode_utxo.enc(&mut writer);
        0u8.enc(&mut writer);
        u32::MAX.enc(&mut writer);
        parent_hash.enc(&mut writer);
        (signal.into() as u32).enc(&mut writer);
        (outcome.into() as u32).enc(&mut writer);
        timestamp.enc(&mut writer);
        UInt256::sha256d(&buffer)
    }

    pub fn data_message(&self) -> Vec<u8> {
        let mut writer: Vec<u8> = Vec::new();
        masternode_utxo.enc(&mut writer);
        if self.chain.params.protocol_version < 70209 {
            // switch to outpoint in 70209
            0u8.enc(&mut writer);
            u32::MAX.enc(&mut writer);
        }
        self.parent_hash.enc(&mut writer);
        (self.outcome.into() as u32).enc(&mut writer);
        (self.signal.into() as u32).enc(&mut writer);
        self.created_at.enc(&mut writer);
        self.signature.enc(&mut writer);
        writer
    }

    pub fn init_with_message(bytes: &[u8], chain: &Chain) -> Option<Self> {
        let offset = &mut 0;
        let masternode_utxo = bytes.read_with::<UTXO>(offset, LE)?;
        if chain.params.protocol_version < 70209 {
            // switch to outpoint in 70209
            let sigscript_size = bytes.read_with::<u8>(offset, LE)?;
            let _sigscript: &[u8] = bytes.read_with(offset, Bytes::Len(sigscript_size as usize))?;
            let _sequence_number = bytes.read_with::<u32>(offset, LE)?;
        }
        let parent_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let outcome = bytes.read_with::<VoteOutcome>(offset, LE)?;
        let signal = bytes.read_with::<VoteSignal>(offset, LE)?;
        let created_at = bytes.read_with::<u64>(offset, LE)?;
        let message_signature_size = bytes.read_with::<u8>(offset, LE)?;
        let signature: &[u8] = bytes.read_with(offset, Bytes::Len(message_signature_size as usize))?;
        Some(Self {
            object: None,
            masternode: None,
            outcome,
            signal,
            created_at,
            signature,
            parent_hash,
            masternode_utxo,
            vote_hash: Self::hash_with_parent_hash(&parent_hash, created_at, &signal, &outcome, &masternode_utxo),
            chain
        })
    }
}
