use diesel::{QueryDsl, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::chain_lock::ChainLock;
use crate::crypto::{UInt256, UInt768};
use crate::schema::{blocks, chain_locks};
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::block::BlockEntity;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::Entity;
use crate::storage::models::masternode::QuorumEntity;

/// "merkleBlock.blockHash == %@"

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct ChainLockEntity {
    pub id: i32,
    pub verified: bool,
    pub signature: UInt768,

    pub chain_id: Option<i32>,
    pub block_id: i32,
    pub quorum_id: Option<i32>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="chain_locks"]
pub struct NewChainLockEntity {
    pub verified: bool,
    pub signature: UInt768,

    pub chain_id: Option<i32>,
    pub block_id: i32,
    pub quorum_id: Option<i32>,
}

impl Entity for ChainLockEntity {
    type ID = chain_locks::id;
    type ChainId = chain_locks::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        chain_locks::dsl::chain_locks
    }
}

impl ChainLockEntity {
    pub fn get_by_block_id(block_id: i32, context: &ManagedContext) -> QueryResult<Self> {
        let predicate = chain_locks::block_id.eq(block_id);
        Self::any(predicate, context)
    }

    pub fn get_by_block_hash(block_hash: &UInt256, context: &ManagedContext) -> QueryResult<Self> {
        BlockEntity::get_by_hash(block_hash, context)
            .and_then(|block| Self::get_by_block_id(block.id, context))
    }

    pub fn count_for_block_hash(block_hash: &UInt256, context: &ManagedContext) -> QueryResult<i64> {
        Self::target()
            .inner_join(BlockEntity::target())
            .filter(blocks::block_hash.eq(block_hash))
            .count()
    }

    pub fn get_block(&self, context: &ManagedContext) -> QueryResult<BlockEntity> {
        if let Some(block_id) = self.block_id {
            BlockEntity::get_by_id(block_id, context)
        } else {
            Err(diesel::result::Error::NotFound)
        }
    }

    pub fn create_if_need(chain_lock: &ChainLock, context: &ManagedContext) -> QueryResult<usize> {
        match Self::count_for_block_hash(&chain_lock.block_hash, context) {
            Ok(0) =>
                BlockEntity::get_by_hash(&chain_lock.block_hash, context)
                    .and_then(|block_entity| ChainEntity::get_chain(chain_lock.chain.r#type(), context)
                        .and_then(|chain_entity| {
                            let mut new_entity = NewChainLockEntity {
                                verified: chain_lock.signature_verified,
                                signature: chain_lock.signature,
                                chain_id: Some(chain_entity.id),
                                block_id: block_entity.id,
                                quorum_id: None
                            };
                            // the quorum might not yet
                            if let Some(b) = &chain_lock.intended_quorum {
                                if let Ok(quorum_entity) = QuorumEntity::get_by_public_key(&b.public_key, context) {
                                    new_entity.quorum_id = Some(quorum_entity.id);
                                }
                            }
                            Self::create_and_get(new_entity, context)
                                .and_then(|chain_lock_entity| chain_lock_entity.update_last_chain_lock_if_need(chain_lock_entity.id, chain_lock, context))
                        })),
            Ok(..) => Ok(0),
            Err(err) => Err(err)
        }
    }

    pub fn update_signature_valid_if_need(chain_lock: &ChainLock, context: &ManagedContext) -> QueryResult<usize> {
        Self::get_by_block_hash(&chain_lock.block_hash, context)
            .and_then(|entity| entity.update_with((chain_locks::verified.eq(true)), context))
    }

}
