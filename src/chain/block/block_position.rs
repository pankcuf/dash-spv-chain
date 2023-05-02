// #[derive(Clone, Copy, Debug)]
// pub enum BlockPosition {
//     Orphan = 0,
//     Terminal = 1,
//     Sync = 2,
//     TerminalSync = 1 | 2
//     // TerminalSync = BlockPosition::Terminal | BlockPosition::Sync
// }

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct BlockPosition: u8 {
        const Orphan = 0;
        const Terminal = 1;
        const Sync = 2;
        const TerminalSync = Self::Terminal.bits() | Self::Sync.bits();
    }
}
