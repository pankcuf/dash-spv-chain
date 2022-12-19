use std::collections::HashSet;
use crate::chain::chain::Chain;
use crate::crypto::UInt256;
use crate::chain::governance;
use crate::chain::network::governance_request_state::GovernanceRequestState;
use crate::chain::network::peer::Peer;

pub const SUPERBLOCK_AVERAGE_TIME: u64 = 2575480;
pub const PROPOSAL_COST: u64 = 500000000;

pub trait PeerGovernanceDelegate {
    fn peer_requested_object(&self, peer: &Peer, object_hash: &UInt256) -> Option<governance::Object>;
    fn peer_requested_vote(&self, peer: &Peer, vote_hash: &UInt256) -> Option<governance::Vote>;
    fn peer_has_governance_object_hashes(&self, peer: &Peer, hashes: Vec<UInt256>);
    fn peer_has_governance_vote_hashes(&self, peer: &Peer, hashes: Vec<UInt256>);
    fn peer_relayed_governance_object(&self, peer: &Peer, object: governance::Object);
    fn peer_relayed_governance_vote(&self, peer: &Peer, vote: governance::Vote);
    fn peer_ignored_governance_sync(&self, peer: &Peer, state: GovernanceRequestState);
}

pub struct GovernanceSyncManager {
    pub chain: &'static Chain,
}
