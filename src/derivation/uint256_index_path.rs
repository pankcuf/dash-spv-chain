use crate::crypto::UInt256;
use crate::derivation::index_path::{IIndexPath, IndexHardSoft};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UInt256IndexPath {
    pub indexes: Vec<UInt256>,
    pub hardened_indexes: Vec<bool>,
}

impl IIndexPath for UInt256IndexPath {
    type Item = UInt256;

    fn new(indexes: Vec<Self::Item>) -> Self {
        Self { indexes, ..Default::default() }
    }

    fn indexes(&self) -> &Vec<Self::Item> {
        &self.indexes
    }

    fn hardened_indexes(&self) -> &Vec<bool> {
        &self.hardened_indexes
    }
}
