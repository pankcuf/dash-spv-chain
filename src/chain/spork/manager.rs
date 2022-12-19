use std::collections::{HashMap, HashSet};
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::chain::spork;
use crate::chain::spork::Spork;
use crate::chain::network::peer::Peer;

pub trait PeerSporkDelegate {
    fn peer_relayed_spork(&self, peer: &Peer, spork: Spork);
    fn peer_has_spork_hashes(&self, peer: &Peer, spork: Vec<UInt256>);
}

pub struct Manager {
    /// this is the time after a successful spork sync, this is not persisted between sessions
    pub last_requested_sporks: f64,
    /// this is the time after a successful spork sync, this is not persisted between sessions
    pub last_synced_sporks: f64,
    /// spork #2
    pub instant_send_active: bool,
    /// spork #15
    pub deterministic_masternode_list_enabled: bool,
    /// spork #17
    pub quorum_dkg_enabled: bool,
    /// spork #19
    pub chain_locks_enabled: bool,
    /// spork #20
    pub llmq_instant_send_enabled: bool,

    pub spork_dictionary: HashMap<spork::Identifier, Spork>,
    pub chain: &'static Chain,
}

impl Manager {
    pub(crate) fn get_sporks(&self) {
        todo!()
    }
}

impl Manager {
    pub fn sporks_updated_signatures(&mut self) -> bool {
        if let Some(update_signature_spork) = self.spork_dictionary.get(&spork::Identifier::Spork6NewSigs) {
            update_signature_spork.value <= self.chain.last_terminal_block_height() as u64
        } else {
            false
        }
    }

}
