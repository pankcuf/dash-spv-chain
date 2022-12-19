use bitcoin_hashes::{Hash, sha256d};
use crate::consensus::Encodable;
use crate::crypto::UInt256;

pub enum MerkleTreeHashFunction {
    SHA256_2 = 0,
    BLAKE3 = 1,
}

pub struct MerkleTree {
    pub tree_element_count: u32,
    pub hashes: Vec<UInt256>,
    pub flags: Vec<u8>,
    pub merkle_root: UInt256,
    pub hash_function: MerkleTreeHashFunction,
}

impl MerkleTree {
    /// true if the given tx hash is included in the block
    pub fn contains_hash(&self, tx_hash: UInt256) -> bool {
        self.hashes.iter().contains(&tx_hash)
    }

    pub fn merkle_root(&self) -> Option<UInt256> {
        let hash_idx = &mut 0;
        let flag_idx = &mut 0;
        self.walk_hash_idx(
            hash_idx,
            flag_idx,
            0,
            |hash, _flag| hash,
            |left, right| {
                let mut buffer: Vec<u8> = Vec::with_capacity(64);
                left.enc(&mut buffer);
                right.unwrap_or(left).enc(&mut buffer);
                Some(UInt256::sha256d(&buffer))
            },
        )
    }

    pub fn has_root(&self, desired_merkle_root: UInt256) -> bool {
        if self.tree_element_count == 0 {
            return true;
        }
        if let Some(root) = self.merkle_root() {
            if root == desired_merkle_root {
                return true;
            }
        }
        false
    }

    pub fn walk_hash_idx<
        BL: Fn(UInt256, Option<UInt256>) -> Option<UInt256> + Copy,
        LL: Fn(Option<UInt256>, bool) -> Option<UInt256> + Copy,
    >(
        &self,
        hash_idx: &mut usize,
        flag_idx: &mut usize,
        depth: i32,
        leaf: LL,
        branch: BL,
    ) -> Option<UInt256> {
        let flags_length = self.flags.len();
        let hashes_length = self.hashes.len();
        if *flag_idx / 8 >= flags_length || *hash_idx >= hashes_length {
            return leaf(None, false);
        }
        let flag = self.flags.as_slice()[*flag_idx / 8] & (1 << (*flag_idx % 8)) != 0;
        *flag_idx += 1;
        if !flag || depth == ceil_log2(self.tree_element_count as i32) {
            let hash = self.hashes.get(*hash_idx).copied();
            *hash_idx += 1;
            return leaf(hash, flag);
        }
        let left = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        let right = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        branch(left.unwrap(), right)
    }

    /// returns an array of the matched tx hashes
    pub fn element_hashes(&self) -> Vec<UInt256> {

        let hash_idx = &mut 0;
        let flag_idx = &mut 0;
        self.walk_hash_idx(
            hash_idx,
            flag_idx,
            0,
            |hash, flag| if flag && hash.is_some() { vec![hash.unwrap()] } else { vec![] },
            |left, right| {
                //return [left arrayByAddingObjectsFromArray:right];
                let mut buffer: Vec<u8> = Vec::with_capacity(64);
                left.enc(&mut buffer);
                right.unwrap_or(left).enc(&mut buffer);
                Some(UInt256::sha256d(&buffer))
            },
        )
    }

}
