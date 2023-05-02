use std::cmp;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use crate::chain::chain::Chain;
use crate::crypto::UInt256;
use crate::chain::masternode::MasternodeList;
use crate::crypto::byte_util::Zeroable;


#[derive(Debug, Default)]
pub struct Store {
    pub masternode_lists_by_block_hash: BTreeMap<UInt256, MasternodeList>,
    pub masternode_lists_by_block_hash_stubs: BTreeSet<UInt256>,
    pub cached_block_hash_heights: HashMap<UInt256, u32>,

    chain: &'static Chain,
}

impl Store {

    pub fn new(chain: &Chain) -> Self {
        Self {
            chain,
            ..Default::default()
        }
    }

    pub fn height_for_block_hash(&mut self, block_hash: &UInt256) -> u32 {
        if block_hash.is_zero() {
            return 0;
        }
        if let Some(&cached_height) = self.cached_block_hash_heights.get(block_hash) {
            return cached_height;
        }
        let chain_height = self.chain.height_for_block_hash(block_hash);
        if chain_height != u32::MAX {
            self.cached_block_hash_heights.insert(*block_hash, chain_height);
        }
        chain_height
    }

    pub fn last_masternode_list_block_height(&mut self) -> u32 {
        let last_hash_stub = self.masternode_lists_by_block_hash.keys().map(|h| self.height_for_block_hash(h)).max();
        let last_hash = self.masternode_lists_by_block_hash_stubs.iter().map(|h| self.height_for_block_hash(h)).max();
        match cmp::max(last_hash, last_hash_stub) {
            Some(l @ 1..=u32::MAX) => l,
            _ => u32::MAX
        }
    }


    pub fn masternode_lists_and_quorums_is_synced(&mut self) -> bool {
        self.last_masternode_list_block_height() != u32::MAX &&
            self.last_masternode_list_block_height() >= self.chain.estimated_block_height() - 16
    }

    pub fn masternode_lists_to_sync(&mut self) -> u32 {
        if self.last_masternode_list_block_height() == u32::MAX {
            32
        } else {
            let diff = self.chain.estimated_block_height() - self.last_masternode_list_block_height();
            if diff < 0 {
                32
            } else {
                cmp::min(32, diff / 24)
            }
        }
    }

}
