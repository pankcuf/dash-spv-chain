use crate::chain::common;
use crate::crypto::UInt256;

#[derive(Debug, Copy, Clone)]
pub struct LLMQTypedHash {
    pub r#type: common::LLMQType,
    pub hash: UInt256,
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct LLMQIndexedHash {
    pub index: u32,
    pub hash: UInt256,
}

impl LLMQIndexedHash {
    pub fn new(hash: UInt256, index: u32) -> Self {
        LLMQIndexedHash { index, hash }
    }
}
