use crate::chain::chain::Chain;
use crate::chain::network::Peer;
use crate::chain::spork::Spork;
use crate::manager::peer_manager;
use crate::platform::identity::identity::Identity;
use crate::platform::identity::invitation::Invitation;
use crate::platform::identity::username_status::UsernameStatus;

pub enum NotificationKey {
    Chain,
    Invitation,
}

pub enum Notification<'a> {
    ChainBlocksDidFinishSyncing(&'a Chain),
    ChainInitialHeadersDidFinishSyncing(&'a Chain),
    ChainStandaloneAddressesDidChange(&'a Chain),
    ChainStandaloneDerivationPathsDidChange(&'a Chain),
    ChainSyncDidStart(&'a Chain, &'a Peer),
    ChainSyncBlocksDidChange(&'a Chain),
    ChainSyncFailed(&'a Chain, &'a Option<peer_manager::Error>),
    ChainTerminalBlocksDidChange(&'a Chain),
    ChainTipDidUpdate(&'a Chain),
    ChainWillStartSyncing(&'a Chain),
    ChainsDidChange,
    GovernanceObjectListDidChange(&'a Chain),
    GovernanceVotesDidChange(&'a Chain),
    GovernanceObjectCountUpdate(&'a Chain),
    GovernanceVoteCountUpdate(&'a Chain),
    IdentityDidUpdate(&'a Chain, &'a Identity, Option<&'a Vec<&'a str>>),
    IdentityDidUpdateUsernameStatus {
        chain: &'a Chain,
        identity: &'a Identity,
        username: &'a String,
        domain: &'a String,
        status: &'a UsernameStatus
    },
    InvitationDidUpdate(&'a Chain, &'a Invitation),
    MasternodeListDidChange(&'a Chain),
    PeersConnectedDidChange(&'a Chain), // DSPeerManagerConnectedPeersDidChangeNotification
    PeersDidChange(&'a Chain), // DSPeerManagerPeersDidChangeNotification
    PeersDownloadPeerDidChange(&'static Chain),
    SporkListDidUpdate {
        chain: &'a Chain,
        old: Option<&'a Spork>,
        new: Option<&'a Spork>,
    },
    TransactionStatusDidChange(&'a Chain), //DSTransactionManagerTransactionStatusDidChangeNotification
    WalletBalanceDidChange,
    WalletsDidChange(&'a Chain),

}


pub enum NotificationInfo {

}

#[derive(Debug, Default)]
pub struct NotificationCenter {
}

impl NotificationCenter {
    pub fn post(notification: Notification) {

    }
}
