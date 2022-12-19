use crate::crypto::UInt256;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Ord, PartialOrd)]
pub struct BlockData {
    pub height: u32,
    pub hash: UInt256,
}
