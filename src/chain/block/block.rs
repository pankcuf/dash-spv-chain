use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::hash::Hasher;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::NaiveDateTime;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::{Insertable, QueryResult, QuerySource, Table};
use diesel::insertable::CanInsertInSingleQuery;
use diesel::sqlite::Sqlite;
use crate::chain::chain::Chain;
use crate::chain::chain_lock::ChainLock;
use crate::chain::checkpoint::Checkpoint;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, Zeroable};
use crate::crypto::UInt256;
use crate::schema::blocks;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::block::NewBlockEntity;
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};
use crate::util::big_uint::{set_compact_le_u32, uint256_add_le, uint256_divide_le};
use crate::util::time::TimeUtil;
use crate::util::TimeUtil;

pub const BLOCK_UNKNOWN_HEIGHT: i32 = i32::MAX;
pub const DGW_PAST_BLOCKS_MIN: i32 = 24;
pub const DGW_PAST_BLOCKS_MAX: i32 = 24;
/// the furthest in the future a block is allowed to be timestamped
pub const MAX_TIME_DRIFT: u64 = 2 * 60 * 60;

pub trait IBlock: EntityConvertible {
    fn height(&self) -> u32;
    fn set_height(&mut self, height: u32);
    fn block_hash(&self) -> UInt256;
    fn merkle_root(&self) -> UInt256;
    fn prev_block(&self) -> UInt256;
    fn target(&self) -> u32;
    fn to_data(&self) -> Vec<u8>;
    fn timestamp(&self) -> u32;
    fn transaction_hashes(&self) -> Vec<UInt256>;
    fn chain_work(&self) -> UInt256;
    fn set_chain_work(&mut self, chain_work: UInt256);
    fn chain_locked(&self) -> bool;
    fn has_unverified_chain_lock(&self) -> bool;
    fn chain_lock_awaiting_processing(&self) -> Option<&ChainLock>;
    // true if merkle tree and timestamp are valid
    // NOTE: This only checks if the block difficulty matches the difficulty target in the header. It does not check if the
    // target is correct for the block's height in the chain. Use verifyDifficultyFromPreviousBlock: for that.
    fn is_valid(&self) -> bool;
    fn can_calculate_difficulty_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> bool;
    fn verify_difficulty_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> (bool, u32);
}

impl Debug for dyn IBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Block {
    pub block_hash: UInt256,
    pub version: u32,
    pub prev_block: UInt256,
    pub merkle_root: UInt256,
    /// time interval since unix epoch
    pub timestamp: u32,
    pub target: u32,
    pub nonce: u32,
    pub total_transactions: u32,
    pub height: u32,
    pub chain: &'static Chain,
    pub chain_work: UInt256,
    /// the matched tx hashes in the block
    pub transaction_hashes: Vec<UInt256>,
    pub chain_locked: bool,
    // pub has_chain_lock_awaiting_saving: bool,
    // pub has_unverified_chain_lock: bool,

    pub chain_lock_awaiting_processing: Option<&'static ChainLock>,
    pub chain_lock_awaiting_saving: Option<&'static ChainLock>,
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self == other || self.block_hash == other.block_hash()
        // return self == obj || ([obj isMemberOfClass:[self class]] && uint256_eq([obj blockHash], _blockHash));
    }
}

impl std::hash::Hash for Block {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.block_hash.as_bytes());
    }
}


impl IBlock for Block {
    fn height(&self) -> u32 {
        self.height
    }
    fn set_height(&mut self, height: u32) {
        self.height = height
    }

    fn block_hash(&self) -> UInt256 {
        self.block_hash
    }

    fn merkle_root(&self) -> UInt256 {
        self.merkle_root
    }

    fn prev_block(&self) -> UInt256 {
        self.prev_block
    }

    fn target(&self) -> u32 {
        self.target
    }

    fn to_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        self.version.enc(&mut buffer);
        self.prev_block.enc(&mut buffer);
        self.merkle_root.enc(&mut buffer);
        self.timestamp.enc(&mut buffer);
        self.target.enc(&mut buffer);
        self.nonce.enc(&mut buffer);
        buffer
    }

    fn timestamp(&self) -> u32 {
        self.timestamp
    }

    fn transaction_hashes(&self) -> Vec<UInt256> {
        self.transaction_hashes.clone()
    }

    fn chain_work(&self) -> UInt256 {
        self.chain_work
    }

    fn set_chain_work(&mut self, chain_work: UInt256) {
        self.chain_work = chain_work;
    }

    fn chain_locked(&self) -> bool {
        self.chain_locked
    }

    fn has_unverified_chain_lock(&self) -> bool {
        self.has_unverified_chain_lock
    }

    fn chain_lock_awaiting_processing(&self) -> Option<&ChainLock> {
        self.chain_lock_awaiting_processing
    }

    fn is_valid(&self) -> bool {
        if !self.is_merle_tree_valid() {
            return false;
        }
        // check if timestamp is too far in future
        // TODO: use estimated network time instead of system time (avoids timejacking attacks and misconfigured time)
        if self.timestamp > (SystemTime::seconds_since_1970() + MAX_TIME_DRIFT) as u32 {
            return false;
        }
        true
    }

    fn can_calculate_difficulty_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> bool {
        let previous_block = previous_blocks.get(&self.prev_block);
        if previous_block.is_none() {
            return false;
        }
        let previous_block = previous_block.unwrap();
        if self.prev_block.is_zero() ||
            previous_block.height() == 0 ||
            previous_block.height() < (DGW_PAST_BLOCKS_MIN + if self.chain.is_devnet_any() { 1 } else { 0 }) as u32 {
            return true;
        }
        if self.chain.params.allow_min_difficulty_blocks {
            // recent block is more than 2 hours old
            // if (self.timestamp > (previousBlock.timestamp + 2 * 60 * 60)) {
            //    return TRUE;
            // }
            // recent block is more than 10 minutes old
            if self.timestamp > previous_block.timestamp + 600 { // 2.5 * 60 * 4
                return true;
            }
        }
        let mut current_block: Option<&dyn IBlock> = Some(&previous_block);
        let mut block_count = 1;
        // loop over the past n blocks, where n == PastBlocksMax
        while current_block.is_some() && current_block.unwrap().height() > 0 && block_count <= DGW_PAST_BLOCKS_MAX {
            current_block = previous_blocks.get(&current_block.unwrap().prev_block());
            block_count += 1;
            if current_block.is_none() {
                println!("Could not retrieve previous block");
                return false;
            }
        }
        true
    }
    fn verify_difficulty_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> (bool, u32) {
        if self.chain.is_devnet_any() {
            return (true, 0);
        }
        let dark_gravity_wave_target = self.dark_gravity_wave_target_with_previous_blocks(previousBlocks);
        let diff = self.target as i32 - dark_gravity_wave_target as i32;
        if i32::abs(diff) > 1 {
            println!("weird difficulty for block at height {} with target (?) (off by {})", self.height, /*uint256_hex(setCompactBE(self.target)),*/ diff);

        }
        // the core client is less precise with a rounding error that can sometimes cause a problem. We are very rarely 1 off
        (i32::abs(diff) < 2, dark_gravity_wave_target)
    }

}

impl EntityConvertible for Block {
    fn to_entity<T, U>(&self) -> U
        where
            T: Table + QuerySource,
            T::FromClause: QueryFragment<Sqlite>,
            U: Insertable<T>, diesel::insertable::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite> {
        NewBlockEntity {
            height: self.height as i32,
            block_hash: self.block_hash,
            chain_work: self.chain_work,
            merkle_root: self.merkle_root,
            prev_block: self.prev_block,
            nonce: self.nonce as i32,
            target: self.target as i32,
            total_transactions: self.total_transactions as i32,
            version: self.version as i32,
            timestamp: NaiveDateTime::from_timestamp_opt(self.timestamp as i64, 0).unwrap(),
            flags: None,
            hashes: None,
            ..Default::default()
            // chain_lock_id: None,
            // chain_id: chain.id,
            // masternode_list_id: self.masternode_i
        }
    }

    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>>
        where
            T: Table,
            V: AsChangeset<Target=T> {
        assert_eq!(self.height == u32::MAX, self.chain_work.is_zero(), "if block height is not set then there should be no aggregated work, and opposite is also true");
        Box::new((
            blocks::block_hash.eq(self.block_hash),
            blocks::version.eq(self.version),
            blocks::prev_block.eq(self.prev_block),
            blocks::merkle_root.eq(self.merkle_root),
            blocks::timestamp.eq(self.timestamp),
            blocks::target.eq(self.target),
            blocks::nonce.eq(self.nonce),
            blocks::total_transactions.eq(self.total_transactions),
            blocks::height.eq(self.height),
            blocks::chain_work.eq(self.chain_work),
        ))
    }

    fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self> {
        todo!()
    }
}

impl Block {
    pub fn init_with_version(version: u32,
                         timestamp: u32,
                         height: u32,
                         block_hash: UInt256,
                         prev_block: UInt256,
                         chain_work: UInt256,
                         merkle_root: UInt256,
                         target: u32,
                         chain: &Chain) -> Self {
        Block {
            block_hash,
            version,
            prev_block,
            merkle_root,
            timestamp,
            target,
            nonce: 0,
            total_transactions: 0,
            height,
            chain,
            chain_work,
            transaction_hashes: vec![],
            chain_locked: false,
            chain_lock_awaiting_processing: None,
            chain_lock_awaiting_saving: None
        }
    }

    pub fn init_with_checkpoint(checkpoint: &Checkpoint, chain: &Chain) -> Self {
        assert!(!checkpoint.chain_work.is_zero(), "Chain work must be set");
        let b = Self::init_with_version(2, checkpoint.timestamp, checkpoint.height, checkpoint.hash, UInt256::MIN, checkpoint.chain_work, checkpoint.merkle_root, checkpoint.target, chain);
        assert!(!b.chain_work.is_zero(), "block should have aggregate work set");
        b
    }

    fn dark_gravity_wave_target_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> u32 {

        // current difficulty formula, darkcoin - based on DarkGravity v3, original work done by evan duffield, modified for iOS
        let previous_block = previous_blocks.get(&self.prev_block()).unwrap();
        let mut actual_timespan = 0i32;
        let mut last_block_time = 0i64;
        let mut block_count = 0u32;
        let mut sum_targets = UInt256::MIN;
        let max_proof_of_work_target = self.chain.params.max_proof_of_work_target;

        if self.prev_block.is_zero() || previous_block.height() == 0 || previous_block.height() < if self.chain.is_devnet_any() { DGW_PAST_BLOCKS_MIN + 1 } else { DGW_PAST_BLOCKS_MIN } as u32 {
            // This is the first block or the height is < PastBlocksMin
            // Return minimal required work. (1e0ffff0)
            return max_proof_of_work_target
        }
        if self.chain.params.allow_min_difficulty_blocks {
            // recent block is more than 2 hours old
            if self.timestamp > previous_block.timestamp() + 2 * 60 * 60 {
                println!("Our block is way ahead of previous block {} > {}", self.timestamp, previous_block.timestamp());
                return max_proof_of_work_target;
            }
            // recent block is more than 10 minutes old
            if self.timestamp > previous_block.timestamp() + 2.5 * 60 * 4 {
                let previous_target = set_compact_le_u32(previous_block.target());
                let new_target = uint256_multiply_uint32_le(previous_target, 10);
                let compact = get_compact_le(new_target);
                if compact > max_proof_of_work_target {
                    println!("Setting desired target to max proof of work");
                    compact = max_proof_of_work_target;
                }
                return compact;
            }
        }

        let mut current_block: Option<&dyn IBlock> = Some(previous_block);
        block_count = 1;
        // loop over the past n blocks, where n == PastBlocksMax

        while current_block.is_some() && current_block.unwrap().height() > 0 && block_count <= DGW_PAST_BLOCKS_MAX as u32 {
            let c_block = current_block.unwrap();
            // Calculate average difficulty based on the blocks we iterate over in this for loop
            if block_count <= DGW_PAST_BLOCKS_MIN as u32 {
                let current_target = set_compact_le_u32(c_block.target());
                sum_targets = uint256_add_le(if block_count == 1 { curent_target } else { sum_targets }, current_target);
            }
            let current_block_time = c_block.timestamp();
            if last_block_time > 0 {
                // Calculate time difference between previous block and current block
                // Increment the actual timespan
                actual_timespan += last_block_time - current_block_time;
            }
            // Set lastBlockTime to the block time for the block in current iteration
            last_block_time = current_block_time as i64;
            // if previous_block == nil {
            //     assert!(current_block);
            //     break;
            // }
            let old_current_block = c_block;
            current_block = previous_blocks.get(&c_block.prev_block());
            if current_block.is_none() {
                println!("Block {} missing for dark gravity wave calculation", old_current_block.height() - 1);
            }
            block_count += 1;
        }
        // UInt256 blockCount256 = ((UInt256){.u64 = {blockCount, 0, 0, 0}});
        let block_count_256 = UInt256::from_u64(block_count);
        // darkTarget is the difficulty
        println!("SumTargets for block {} is {}, blockCount is {}", self.height, sum_targets, block_count_256);
        let mut dark_target = uint256_divide_le(sum_targets, block_count_256);
        // nTargetTimespan is the time that the CountBlocks should have taken to be generated.
        let target_timespan = (block_count - 1) * 60 * 2.5;
        //DSLog(@"Original dark target for block %d is %@", self.height, uint256_hex(darkTarget));
        //DSLog(@"Max proof of work is %@", uint256_hex(self.chain.maxProofOfWork));
        // Limit the re-adjustment to 3x or 0.33x
        // We don't want to increase/decrease diff too much.
        let span_d_3 = target_timespan / 3.0f64;
        if actual_timespan < span_d_3 {
            actual_timespan = span_d_3;
        }
        let span_m_3 = target_timespan * 3.0f64;
        if actual_timespan > span_m_3 {
            actual_timespan = span_m_3;
        }

        dark_target = uint256_multiply_uint32_le(dark_target, actual_timespan);
        //UInt256 nTargetTimespan256 = ((UInt256){.u64 = {nTargetTimespan, 0, 0, 0}});
        let target_timespan_256 = UInt256::from_u64(target_timespan);

        //DSLog(@"Middle dark target for block %d is %@", self.height, uint256_hex(darkTarget));
        //DSLog(@"nTargetTimespan256 for block %d is %@", self.height, uint256_hex(nTargetTimespan256));
        // Calculate the new difficulty based on actual and target timespan.
        dark_target = uint256_divide_le(dark_target, target_timespan_256);

        //DSLog(@"Final dark target for block %d is %@", self.height, uint256_hex(darkTarget));

        // If calculated difficulty is lower than the minimal diff, set the new difficulty to be the minimal diff.
        //if (uint256_sup(darkTarget, self.chain.maxProofOfWork)) {
        if dark_target > max_proof_of_work {
            println!("Found a block with minimum difficulty");
            return max_proof_of_work_target;
        }

        // Return the new diff.
        get_compact_le(dark_target)
    }

    pub fn set_chain_locked_with_equivalent_block(&mut self, block: &dyn IBlock) {
        if block.block_hash() == self.block_hash() {
            self.chain_locked |= block.chain_locked();
            self.has_unverified_chain_lock |= block.has_unverified_chain_lock();
            if self.has_unverified_chain_lock() {
                self.chain_lock_awaiting_processing = block.chain_lock_awaiting_processing();
            }
        }
    }

    pub fn set_chain_locked_with_chain_lock(&mut self, chain_lock: Option<&mut ChainLock>) {
        match chain_lock {
            Some(chain_lock) => {
                self.chain_locked = chain_lock.signature_verified;
                self.has_unverified_chain_lock = !chain_lock.signature_verified;
                if self.has_unverified_chain_lock {
                    self.chain_lock_awaiting_processing = Some(chain_lock);
                } else {
                   self.chain_lock_awaiting_processing = None;
                }
                if !chain_lock.saved {
                    chain_lock.save_initial();
                    if !chain_lock.saved {
                        // it is still not saved
                        self.chain_lock_awaiting_saving = Some(chain_lock);
                    }
                }
            },
            None => {
                self.chain_locked = false;
                self.has_unverified_chain_lock = false;
            }
        }
    }

    pub fn has_chain_lock_awaiting_saving(&self) -> bool {
        self.chain_lock_awaiting_saving.is_some()
    }

    pub fn save_associated_chain_lock(&mut self) -> bool {
        match self.chain_lock_awaiting_saving {
            Some(mut awaiting_chain_lock) if !awaiting_chain_lock.saved => {
                awaiting_chain_lock.save_initial();
                if awaiting_chain_lock.saved {
                    self.chain_lock_awaiting_saving = None;
                    true
                } else {
                    false
                }
            },
            _ => true
        }
    }

}

