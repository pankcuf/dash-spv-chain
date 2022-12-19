use std::collections::HashMap;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use diesel::{Insertable, QueryResult, Table};
use crate::crypto::byte_util::merkle_root_from_hashes;
use crate::crypto::UInt256;
use crate::chain::block::{Block, IBlock};
use crate::chain::chain_lock::ChainLock;
use crate::chain::tx::transaction::ITransaction;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};

#[derive(Clone, Copy, Debug)]
pub struct FullBlock {
    pub base: Block,
    pub transactions: Vec<dyn ITransaction>,
}

impl EntityConvertible for FullBlock {
    fn to_entity<T, U>(&self) -> U where T: Table, diesel::query_source::FromClause: QueryFragment<Sqlite>, U: Insertable<T>, diesel::insertable::Values: IValues {
        todo!()
    }

    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>> where T: Table, V: AsChangeset<Target=T> {
        todo!()
    }

    fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self> {
        todo!()
    }
}

impl IBlock for FullBlock {
    fn height(&self) -> u32 {
        self.base.height()
    }

    fn set_height(&mut self, height: u32) {
        self.base.set_height(height)
    }

    fn block_hash(&self) -> UInt256 {
        self.base.block_hash()
    }

    fn merkle_root(&self) -> UInt256 {
        self.base.merkle_root()
    }

    fn prev_block(&self) -> UInt256 {
        self.base.prev_block()
    }

    fn target(&self) -> u32 {
        self.base.target
    }

    fn to_data(&self) -> Vec<u8> {
        self.base.to_data()
    }

    fn timestamp(&self) -> u32 {
        self.base.timestamp()
    }

    fn transaction_hashes(&self) -> Vec<UInt256> {
        self.transactions.iter().map(|tx| tx.tx_hash()).collect()
    }

    fn chain_work(&self) -> UInt256 {
        self.base.chain_work()
    }

    fn set_chain_work(&mut self, chain_work: UInt256) {
        self.base.set_chain_work(chain_work)
    }

    fn chain_locked(&self) -> bool {
        self.base.chain_locked()
    }

    fn has_unverified_chain_lock(&self) -> bool {
        self.base.has_unverified_chain_lock()
    }

    fn chain_lock_awaiting_processing(&self) -> Option<&ChainLock> {
        self.base.chain_lock_awaiting_processing()
    }

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn can_calculate_difficulty_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> bool {
        self.base.can_calculate_difficulty_with_previous_blocks(previous_blocks)
    }

    fn verify_difficulty_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> (bool, u32) {
        self.base.verify_difficulty_with_previous_blocks(previous_blocks)
    }
}

impl FullBlock {

    pub fn is_merkle_tree_valid(&self) -> bool {
        if let Some(root) = merkle_root_from_hashes(self.transaction_hashes()) {
            if self.base.total_transactions > 0 && root != self.base.merkle_root() {
                false
            } else {
                true
            }
        } else {
            false
        }
    }

}
