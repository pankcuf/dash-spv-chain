use std::cmp::{max, min};
use std::collections::HashMap;
use crate::chain::chain::Chain;
use crate::crypto::UInt256;
use crate::models::{LLMQEntry, MasternodeList};
use crate::chain::tx::transaction::ITransaction;
use crate::chain::masternode::local_masternode::LocalMasternode;
use crate::chain::masternode::store::Store;
use crate::chain::network::peer::Peer;
use crate::chain::tx::provider_registration_transaction::ProviderRegistrationTransaction;

pub trait PeerMasternodeDelegate {
    fn peer_relayed_masternode_diff_message(&self, peer: &Peer, message: &[u8]);
    fn peer_relayed_quorum_rotation_info_message(&self, peer: &Peer, message: &[u8]);
}

pub struct MasternodeManager {
    pub chain: &'static Chain,
    pub store: Store,
    pub local_masternodes_dictionary_by_registration_transaction_hash: HashMap<UInt256, LocalMasternode>,
}

impl MasternodeManager {
    pub(crate) fn quorum_entry_for_chain_lock_request_id(&self, request_id: Option<UInt256>, block_height_offset: u32) -> Option<&LLMQEntry> {
        todo!()
    }
}

impl MasternodeManager {
    pub(crate) fn quorum_entry_for_instant_send_request_id(&self, request_id: &UInt256, block_height_offset: u32) -> Option<&LLMQEntry> {
        todo!()
    }
}

impl MasternodeManager {
    pub(crate) fn start_sync(&self) {
        todo!()
    }

    pub(crate) fn last_masternode_list_block_height(&self) -> _ {
        todo!()
    }

    pub(crate) fn wipe_masternode_info(&self) {
        todo!()
    }

    pub(crate) fn wipe_local_masternode_info(&self) {
        todo!()
    }

    pub fn recent_masternode_lists(&self) -> Vec<MasternodeList> {
        self.store.masternode_lists_by_block_hash.values().collect()
    }

    pub fn masternode_list_retrieval_queue_count(&self) -> usize {
        todo!("impl list diff service");
        //return [self.masternodeListDiffService retrievalQueueCount] + [self.quorumRotationService retrievalQueueCount];
    }

    pub fn masternode_list_retrieval_queue_max_amount(&self) -> usize {
        todo!("impl list diff service")
        //return [self.masternodeListDiffService retrievalQueueMaxAmount] + [self.quorumRotationService retrievalQueueMaxAmount];
    }

    pub fn masternode_list_and_quorums_sync_progress(&self) -> f64 {
        let amount_left = self.masternode_list_retrieval_queue_count() as f64;
        let max_amount = self.masternode_list_retrieval_queue_max_amount() as f64;
        if !amountLeft {
            return self.store.masternode_lists_and_quorums_is_synced;
        }
        max(min((max_amount - amount_left) / max_amount, 1f64), 0f64)
    }

    pub fn local_masternode_from_provider_registration_transaction(&mut self, transaction: &ProviderRegistrationTransaction, save: bool) -> Option<&LocalMasternode> {
        // First check to see if we have a local masternode for this provider registration hash
        let tx_hash = transaction.tx_hash();
        if let Some(local_masternode) = self.local_masternodes_dictionary_by_registration_transaction_hash.get(&tx_hash) {
            //todo Update keys
            return Option::from(local_masternode)
        }
        let local_masternode = LocalMasternode::init_with_provider_registration_transaction(transaction);
        if local_masternode.no_local_wallet() {
            return None;
        }
        self.local_masternodes_dictionary_by_registration_transaction_hash.insert(tx_hash, local_masternode);
        if save {
            local_masternode.save();
        }
        Some(&local_masternode)
    }

    pub fn local_masternode_having_provider_registration_transaction_hash(&self, hash: &UInt256) -> Option<&LocalMasternode> {
        self.local_masternodes_dictionary_by_registration_transaction_hash.get(hash)
    }



}
