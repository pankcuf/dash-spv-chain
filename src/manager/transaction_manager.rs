use std::collections::HashSet;
use crate::crypto::UInt256;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::block::{IBlock, MerkleBlock};
use crate::chain::chain::Chain;
use crate::chain::chain_lock::ChainLock;
use crate::chain::merkle_block::MerkleBlock;
use crate::chain::network::peer::Peer;
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;

pub trait PeerTransactionDelegate {
    /// called when the peer relays either a merkleblock or a block header, headers will have 0 totalTransactions
    fn peer_relayed_header(&self, peer: &Peer, block: &MerkleBlock);
    fn peer_relayed_block(&self, peer: &Peer, block: &MerkleBlock);
    fn peer_relayed_chain_lock(&self, peer: &Peer, chain_lock: &ChainLock);
    fn peer_relayed_too_many_orphan_blocks(&self, peer: &Peer, orphan_block_count: usize);
    fn peer_relayed_not_found_messages_with_transaction_hashes(&self, peer: &Peer, tx_hashes: Vec<UInt256>, block_hashes: Vec<UInt256>);
    fn peer_relayed_transaction(&self, peer: &Peer, transaction: &dyn ITransaction, block: Option<dyn IBlock>);
    fn peer_relayed_instant_send_transaction_lock(&self, peer: &Peer, transaction_lock: InstantSendTransactionLock);
    fn peer_requested_transaction(&self, peer: &Peer, tx_hash: &UInt256) -> Option<dyn ITransaction>;
    fn peer_has_transaction_with_hash(&self, peer: &Peer, tx_hash: &UInt256);
    fn peer_rejected_transaction(&self, peer: &Peer, tx_hash: &UInt256, code: u8);
    fn peer_has_instant_send_lock_hashes(&self, peer: &Peer, hashes: HashSet<UInt256>);
    fn peer_has_instant_send_deterministic_lock_hashes(&self, peer: &Peer, hashes: HashSet<UInt256>);
    fn peer_has_chain_lock_hashes(&self, peer: &Peer, hashes: HashSet<UInt256>);
    fn peer_set_fee_per_byte(&self, peer: &Peer, fee_per_kb: u64);
}

pub struct TransactionManager {
    pub chain: &'static Chain,
}

impl PeerTransactionDelegate for TransactionManager {
    fn peer_relayed_header(&self, peer: &Peer, block: &MerkleBlock) {
        todo!()
    }

    fn peer_relayed_block(&self, peer: &Peer, block: &MerkleBlock) {
        todo!()
    }

    fn peer_relayed_chain_lock(&self, peer: &Peer, chain_lock: &ChainLock) {
        todo!()
    }

    fn peer_relayed_too_many_orphan_blocks(&self, peer: &Peer, orphan_block_count: usize) {
        todo!()
    }

    fn peer_relayed_not_found_messages_with_transaction_hashes(&self, peer: &Peer, tx_hashes: Vec<UInt256>, block_hashes: Vec<UInt256>) {
        todo!()
    }

    fn peer_relayed_transaction(&self, peer: &Peer, transaction: &dyn ITransaction, block: Option<dyn IBlock>) {
        todo!()
    }

    fn peer_relayed_instant_send_transaction_lock(&self, peer: &Peer, transaction_lock: InstantSendTransactionLock) {
        todo!()
    }

    fn peer_requested_transaction(&self, peer: &Peer, tx_hash: &UInt256) -> Option<dyn ITransaction> {
        todo!()
    }

    fn peer_has_transaction_with_hash(&self, peer: &Peer, tx_hash: &UInt256) {
        todo!()
    }

    fn peer_rejected_transaction(&self, peer: &Peer, tx_hash: &UInt256, code: u8) {
        todo!()
    }

    fn peer_has_instant_send_lock_hashes(&self, peer: &Peer, hashes: Vec<UInt256>) {
        todo!()
    }

    fn peer_has_instant_send_deterministic_lock_hashes(&self, peer: &Peer, hashes: Vec<UInt256>) {
        todo!()
    }

    fn peer_has_chain_lock_hashes(&self, peer: &Peer, hashes: Vec<UInt256>) {
        todo!()
    }

    fn peer_set_fee_per_byte(&self, peer: &Peer, fee_per_kb: u64) {
        todo!()
    }
}
