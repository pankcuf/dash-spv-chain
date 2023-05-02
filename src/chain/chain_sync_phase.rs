#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ChainSyncPhase {
    Offline = 0,
    InitialTerminalBlocks,
    ChainSync,
    Synced
}

impl Default for ChainSyncPhase {
    fn default() -> Self {
        ChainSyncPhase::Offline
    }
}
