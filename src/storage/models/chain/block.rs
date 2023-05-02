use std::collections::HashMap;
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::block::IBlock;
use crate::chain::common::ChainType;
use crate::crypto::UInt256;
use crate::schema::blocks;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::Entity;
use crate::storage::models::masternode::QuorumEntity;

/// queries:
/// "chain == %@"
/// "chain == %@ && (height == %@)"
/// "(chain == %@) && (blockHash == %@)"
/// "chain == %@ && (blockHash == %@ || blockHash == %@ )"
/// "(chain == %@) && (height > %u) && !(blockHash in %@)"
/// "(chain == %@) && masternodeList == NIL && (usedByQuorums.@count == 0) && !(blockHash in %@)"
/// "blockHash == %@"
/// "blockHash in %@"
/// indexation:
/// "height" DESC
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = blocks)]
pub struct BlockEntity {
    pub id: i32,
    pub chain_id: i32,
    pub chain_lock_id: Option<i32>,
    pub masternode_list_id: Option<i32>,
    pub height: i32,
    pub block_hash: UInt256,
    pub chain_work: UInt256,
    pub merkle_root: UInt256,
    pub prev_block: UInt256,
    pub nonce: i32,
    pub target: i32,
    pub total_transactions: i32,
    pub version: i32,
    pub timestamp: NaiveDateTime,

    pub flags: Option<Vec<u8>>,
    pub hashes: Option<Vec<u8>>,

}

#[derive(Insertable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = blocks)]
pub struct NewBlockEntity {
    pub chain_id: i32,
    pub chain_lock_id: Option<i32>,
    pub masternode_list_id: Option<i32>,
    pub height: i32,
    pub block_hash: UInt256,
    pub chain_work: UInt256,
    pub merkle_root: UInt256,
    pub prev_block: UInt256,
    pub nonce: i32,
    pub target: i32,
    pub total_transactions: i32,
    pub version: i32,
    pub timestamp: NaiveDateTime,

    pub flags: Option<Vec<u8>>,
    pub hashes: Option<Vec<u8>>,
}

impl Entity for BlockEntity {
    type ID = blocks::id;
    // type ChainId = blocks::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         blocks::dsl::blocks
    }
}

impl BlockEntity {
    fn chain_entity(chain_type: ChainType, context: &ManagedContext) -> QueryResult<ChainEntity> {
        ChainEntity::get_chain(chain_type, context)
    }

    pub fn get_by_hash(block_hash: &UInt256, context: &ManagedContext) -> QueryResult<BlockEntity> {
        let predicate = blocks::block_hash.eq(block_hash);
        Self::any(predicate, context)
    }

    pub fn delete_orphan_blocks(chain_type: ChainType, from_height: u32, keep_block_hashes: Vec<UInt256>, context: &ManagedContext) -> QueryResult<usize> {
        // "(chain == %@) && (height > %u) && !(blockHash in %@)",
        // [self chainEntityInContext:self.chainManagedObjectContext],
        // startHeight,
        // blocks.allKeys];
        Self::chain_entity(chain_type, context)
            .and_then(|chain|
                Self::delete_by(
                    blocks::chain_id.eq(chain.id)
                        .and(blocks::height.ge(from_height))
                        .and(blocks::block_hash.ne_all(keep_block_hashes)),
                    context))
    }

    pub fn delete_blocks(chain_type: ChainType, keep_block_hashes: Vec<UInt256>, context: &ManagedContext) -> QueryResult<usize> {
        Self::chain_entity(chain_type, context)
            .and_then(|chain| BlockEntity::read(
                blocks::chain_id.eq(chain.id)
                    .and(blocks::block_hash.ne_all(keep_block_hashes)), context)
                .and_then(|blocks| Self::delete_by_ids(
                    blocks.iter()
                        .filter_map(|block|
                            match QuorumEntity::quorums_for_block_id(block.id, context) {
                                Ok(quorums) if !quorums.is_empty() => Some(block.id),
                                _ => None
                            })
                        .collect(),
                    context)))
    }

    pub fn update_blocks(chain_type: ChainType, blocks: &mut HashMap<UInt256, &dyn IBlock>, context: &ManagedContext) -> QueryResult<usize> {
        Self::chain_entity(chain_type, context)
            .and_then(|chain|
                blocks.iter()
                    .filter_map(|(block_hash, block)|
                        match Self::any(blocks::block_hash.eq(block_hash), context) {
                            Ok(entity) => match Self::update(Self::ID.eq(entity.id), block.to_update_values(), context) {
                                Ok(count) if count > 0 => {
                                    blocks.remove(block_hash);
                                    Some(count)
                                },
                                _ => None
                            },
                            Err(err) => {
                                let mut entity: NewBlockEntity = block.to_entity();
                                entity.chain_id = chain.id;
                                Self::create(&entity, context)
                            }
                        })
                    .collect())
    }

    pub fn get_last_terminal_blocks(chain_type: ChainType, recent: u32, context: &ManagedContext) -> QueryResult<Vec<BlockEntity>> {
        // [DSMerkleBlockEntity lastTerminalBlocks:
        //     KEEP_RECENT_TERMINAL_BLOCKS
        // onChainEntity:[self chainEntityInContext:self.chainManagedObjectContext]]) {
        todo!()
    }

    pub fn get_last_terminal_block(chain_type: ChainType, context: &ManagedContext) -> QueryResult<BlockEntity> {
        todo!()
    }
}
