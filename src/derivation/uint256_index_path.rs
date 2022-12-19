use std::fmt::Display;
use crate::consensus::Encodable;
use crate::crypto::byte_util::AsBytesVec;
use crate::crypto::UInt256;
use crate::derivation::derivation_path::BIP32_HARD;

pub trait IIndexPath {
    type Item: Display;

    fn new(indexes: Vec<Self::Item>) -> Self;
    fn index_path_with_index(index: Self::Item);
    fn index_path_with_indexes(indexes: Vec<Self::Item>) -> Self;

    fn indexes(&self) -> &Vec<Self::Item>;
    fn is_empty(&self) -> bool {
        self.indexes().is_empty()
    }
    fn length(&self) -> usize {
        self.indexes().len()
    }
    fn index_path_string(&self) -> String {
        if self.is_empty() {
            format!("")
        } else {
            self.indexes().into_iter().map(|index| format!("{}", index)).join(".")
        }
    }
    fn harden_all_items(&self) -> IndexPath<Self::Item>;
    fn soften_all_items(&self) -> IndexPath<Self::Item>;
}

pub struct IndexPath<T> {
    pub indexes: Vec<T>
}

impl<T> AsBytesVec for IndexPath<T> where T: AsBytesVec + Encodable {
    fn as_bytes_vec(&self) -> &Vec<u8> {
        let mut writer = Vec::<u8>::new();
        self.indexes.iter().for_each(|index| {
            index.enc(&mut writer);
        });
        &writer
    }
}

impl<T> IIndexPath for IndexPath<T> {
    type Item = T;

    fn new(indexes: Vec<Self::Item>) -> Self {
        Self { indexes }
    }

    fn index_path_with_index(index: Self::Item) -> Self {
        Self::new(vec![index])
    }

    fn index_path_with_indexes(indexes: Vec<Self::Item>) -> Self {
        Self::new(indexes)
    }

    fn indexes(&self) -> &Vec<Self::Item> {
        &self.indexes
    }

    fn harden_all_items(&self) -> IndexPath<Self::Item> {
        let mut indexes = self.indexes.clone();
        for i in 0..self.length() {
            indexes[i] |= BIP32_HARD;
        }
        IndexPath::index_path_with_indexes(indexes)
    }

    fn soften_all_items(&self) -> IndexPath<Self::Item> {
        let mut indexes = self.indexes.clone();
        for i in 0..self.length() {
            indexes[i] &= !BIP32_HARD;
        }
        IndexPath::index_path_with_indexes(indexes)
    }

}

pub struct UInt256IndexPath {
    // todo: migrate to raw bytes
    pub indexes: Vec<UInt256>
}

impl IIndexPath for UInt256IndexPath {
    type Item = UInt256;

    fn new(indexes: Vec<Self::Item>) -> Self {
        Self { indexes }
    }
    fn index_path_with_index(index: Self::Item) -> Self {
        Self::index_path_with_indexes(vec![index])
    }

    fn index_path_with_indexes(indexes: Vec<Self::Item>) -> Self {
        Self { indexes }
    }

    fn indexes(&self) -> &Vec<Self::Item> {
        &self.indexes
    }

    fn harden_all_items(&self) -> IndexPath<Self::Item> {
        todo!()
    }

    fn soften_all_items(&self) -> IndexPath<Self::Item> {
        todo!()
    }
}
