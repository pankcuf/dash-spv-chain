use std::fmt::Debug;
use crate::chain::chain::Chain;
use crate::crypto::UInt256;
use crate::chain::governance;
use crate::chain::governance::{Object, Vote};
use crate::chain::network::governance_request_state::GovernanceRequestState;
use crate::chain::network::Peer;
use crate::chain::tx::ITransaction;

pub const SUPERBLOCK_AVERAGE_TIME: u64 = 2575480;
pub const PROPOSAL_COST: u64 = 500000000;

pub trait PeerGovernanceDelegate: Send + Sync + Debug + Default where Self: Sized {
    fn peer_requested_object(&self, peer: &Peer, object_hash: &UInt256) -> Option<governance::Object>;
    fn peer_requested_vote(&self, peer: &Peer, vote_hash: &UInt256) -> Option<governance::Vote>;
    fn peer_has_governance_object_hashes(&self, peer: &Peer, hashes: Vec<UInt256>);
    fn peer_has_governance_vote_hashes(&self, peer: &Peer, hashes: Vec<UInt256>);
    fn peer_relayed_governance_object(&self, peer: &Peer, object: governance::Object);
    fn peer_relayed_governance_vote(&self, peer: &Peer, vote: governance::Vote);
    fn peer_ignored_governance_sync(&self, peer: &Peer, state: GovernanceRequestState);
}

#[derive(Debug, Default)]
pub struct GovernanceSyncManager {
    pub chain: &'static Chain,
    pub current_governance_sync_object: Option<governance::Object>,

    // @property (nonatomic, strong) NSMutableOrderedSet<NSData *> *known_governance_object_hashes_for_existing_governance_objects;
    known_governance_object_hashes_for_existing_governance_objects: Vec<UInt256>,
    governance_objects: Vec<governance::Object>,
    need_vote_sync_governance_objects: Vec<governance::Object>,
}

impl<'a> Default for &'a GovernanceSyncManager {
    fn default() -> Self {
        &GovernanceSyncManager::default()
    }
}

impl PeerGovernanceDelegate for GovernanceSyncManager {
    fn peer_requested_object(&self, peer: &Peer, object_hash: &UInt256) -> Option<Object> {
        todo!()
    }

    fn peer_requested_vote(&self, peer: &Peer, vote_hash: &UInt256) -> Option<Vote> {
        todo!()
    }

    fn peer_has_governance_object_hashes(&self, peer: &Peer, hashes: Vec<UInt256>) {
        todo!()
    }

    fn peer_has_governance_vote_hashes(&self, peer: &Peer, hashes: Vec<UInt256>) {
        todo!()
    }

    fn peer_relayed_governance_object(&self, peer: &Peer, object: Object) {
        todo!()
    }

    fn peer_relayed_governance_vote(&self, peer: &Peer, vote: Vote) {
        todo!()
    }

    fn peer_ignored_governance_sync(&self, peer: &Peer, state: GovernanceRequestState) {
        todo!()
    }
}

impl GovernanceSyncManager {
    pub(crate) fn start_governance_sync(&self) {
        todo!()
    }
}

impl GovernanceSyncManager {
    pub(crate) fn wipe_governance_info(&mut self) {
        self.governance_objects.clear();
        self.need_vote_sync_governance_objects.clear();
        self.current_governance_sync_object = None;
        self.known_governance_object_hashes_for_existing_governance_objects.clear();
    }
}
