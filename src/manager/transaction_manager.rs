use std::collections::HashMap;
use std::fmt::Debug;
use futures::future::Shared;
use crate::crypto::UInt256;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::block::{IBlock, MerkleBlock};
use crate::chain::chain::Chain;
use crate::chain::chain_lock::ChainLock;
use crate::chain::network::{BloomFilter, Peer};
use crate::chain::tx;
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::chain::tx::TX_UNCONFIRMED;

pub trait PeerTransactionDelegate {
    /// called when the peer relays either a merkleblock or a block header, headers will have 0 totalTransactions
    fn peer_relayed_header(&self, peer: &Peer, block: &MerkleBlock);
    fn peer_relayed_block(&self, peer: &Peer, block: &MerkleBlock);
    fn peer_relayed_chain_lock(&self, peer: &Peer, chain_lock: &ChainLock);
    fn peer_relayed_too_many_orphan_blocks(&self, peer: &Peer, orphan_block_count: usize);
    fn peer_relayed_not_found_messages_with_transaction_hashes(&self, peer: &Peer, tx_hashes: Vec<UInt256>, block_hashes: Vec<UInt256>);
    fn peer_relayed_transaction(&self, peer: &Peer, transaction: &dyn ITransaction, block: Option<&dyn IBlock>);
    fn peer_relayed_instant_send_transaction_lock(&self, peer: &Peer, transaction_lock: InstantSendTransactionLock);
    fn peer_requested_transaction(&self, peer: &Peer, tx_hash: &UInt256) -> Option<&dyn ITransaction>;
    fn peer_has_transaction_with_hash(&self, peer: &Peer, tx_hash: &UInt256);
    fn peer_rejected_transaction(&self, peer: &Peer, tx_hash: &UInt256, code: u8);
    fn peer_has_instant_send_lock_hashes(&self, peer: &Peer, hashes: Vec<UInt256>);
    fn peer_has_instant_send_deterministic_lock_hashes(&self, peer: &Peer, hashes: Vec<UInt256>);
    fn peer_has_chain_lock_hashes(&self, peer: &Peer, hashes: Vec<UInt256>);
    fn peer_set_fee_per_byte(&self, peer: &Peer, fee_per_kb: u64);
}

#[derive(Debug, Default)]
pub struct TransactionManager {
    pub chain: Shared<Chain>,
    pub published_tx: HashMap<UInt256, tx::Kind>
}

impl<'a> Default for &'a TransactionManager {
    fn default() -> Self {
        &TransactionManager::default()
    }
}

impl TransactionManager {
    pub(crate) fn fetch_mempool_from_network(&self) {
        todo!()
    }
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

    fn peer_relayed_transaction(&self, peer: &Peer, transaction: &dyn ITransaction, block: Option<&dyn IBlock>) {
        todo!()
    }

    fn peer_relayed_instant_send_transaction_lock(&self, peer: &Peer, transaction_lock: InstantSendTransactionLock) {
        todo!()
    }

    fn peer_requested_transaction(&self, peer: &Peer, tx_hash: &UInt256) -> Option<&dyn ITransaction> {
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

impl TransactionManager {
    // MARK: - DSChainTransactionsDelegate

    pub fn chain_did_set_block_height(&self, height: u32, timestamp: u64, tx_hashes: &Vec<UInt256>, updated_tx_hashes: &Vec<UInt256>) {
        if height != TX_UNCONFIRMED as u32 {
            // remove confirmed tx from publish list and relay counts
            todo!()
            // [self.publishedTx removeObjectsForKeys:transactionHashes];
            // [self.publishedCallback removeObjectsForKeys:transactionHashes];
            // [self.txRelays removeObjectsForKeys:transactionHashes];
        }

    }

    pub fn chain_was_wiped(&mut self) {
        // self.tx_relays.clear();
        // self.published_tx.clear();
        // self.published_callback.clear();
        // self.bloom_filter = None;
    }

    // This returns the bloom filter for the peer, currently the filter is only tweaked per peer,
    // and we only cache the filter of the download peer.
    // It makes sense to keep this in this class because it is not a property of the chain, but
    // instead of a ephemeral item used in the synchronization of the chain.
    pub fn transactions_bloom_filter_for_peer_hash(&self, hash: u32) -> BloomFilter {
        todo!()
    }

    // unconfirmed transactions that aren't in the mempools of any of connected peers have likely dropped off the network
    pub fn remove_unrelayed_transactions_from_peer(&self, peer: &Peer) {

    }
}
