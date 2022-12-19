pub mod local_masternode;
pub mod masternode;
pub mod masternode_list;
pub mod quorum;
pub mod llmq_snapshot;

pub use self::local_masternode::{LocalMasternodeEntity, NewLocalMasternodeEntity};
pub use self::masternode::{MasternodeEntity, NewMasternodeEntity};
pub use self::masternode_list::{MasternodeListEntity, NewMasternodeListEntity};
pub use self::quorum::{QuorumEntity, NewQuorumEntity};
