#[derive(Clone, Copy, Debug)]
pub enum BlockPosition {
    Orphan = 0,
    Terminal = 1,
    Sync = 2,
    TerminalSync = BlockPosition::Terminal | BlockPosition::Sync
}
