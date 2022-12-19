use crate::crypto::UInt384;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct OperatorPublicKey {
    pub data: UInt384,
    pub version: u16,
}

impl PartialEq for OperatorPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self == other || (self.data == other.data && self.version == other.version)
    }
}
