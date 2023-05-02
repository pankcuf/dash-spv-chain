use diesel::{BoolExpressionMethods, ExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::common::ChainType;
use crate::chain::spork::Spork;
use crate::crypto::UInt256;
use crate::schema::sporks;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::Entity;

/// queries:
/// (sporkhash) "(sporkHash.chain == %@)"
/// indexation:

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = sporks)]
pub struct SporkEntity {
    pub id: i32,
    pub identifier: i32,
    pub time_signed: i64,
    pub value: i64,
    pub spork_hash: UInt256,
    pub signature: Vec<u8>,

    pub marked_for_retrieval: i16,

    pub chain_id: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = sporks)]
pub struct NewSporkEntity {
    pub identifier: i32,
    pub time_signed: i64,
    pub value: i64,

    pub spork_hash: UInt256,
    pub signature: Vec<u8>,

    pub marked_for_retrieval: i16,

    pub chain_id: i32,
}

impl Entity for SporkEntity {
    type ID = sporks::id;
    // type ChainId = sporks::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         sporks::dsl::sporks
    }

}

impl SporkEntity {

    pub fn get_by_spork_hash(hash: &UInt256, chain_id: i32, context: &ManagedContext) -> QueryResult<SporkEntity> {
        let predicate = sporks::spork_hash.eq(hash).and(sporks::chain_id.eq(chain_id));
        Self::any(predicate, context)
    }

    pub fn update_with_spork(spork: &Spork, hash: UInt256, context: &ManagedContext) -> QueryResult<usize> {
        ChainEntity::get_chain(spork.chain.r#type(), context)
            .and_then(|chain_entity| Self::get_by_spork_hash(&hash, chain_entity.id, context)
                .and_then(|entity| entity.update_with(spork.update_values_with_hash(&hash), context))
                .or_else(|err| if err == diesel::result::Error::NotFound {
                    Self::create(spork.to_entity_with_hash(hash, chain_entity.id), context)
                } else {
                    Err(err)
                }))
    }

    pub fn get_by_chain_id(chain_id: i32, context: &ManagedContext) -> QueryResult<Vec<SporkEntity>> {
        Self::read(sporks::chain_id.eq(chain_id), context)
    }

    pub fn get_all_for_chain_type(chain_type: ChainType, context: &ManagedContext) -> QueryResult<Vec<SporkEntity>> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity| Self::get_by_chain_id(chain_entity.id, context))
    }

}
