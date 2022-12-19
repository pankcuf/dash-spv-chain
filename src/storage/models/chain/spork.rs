use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::sporks;
use crate::storage::models::entity::Entity;

/// queries:
/// (sporkhash) "(sporkHash.chain == %@)"
/// indexation:

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct SporkEntity {
    pub id: i32,
    pub identifier: i32,
    pub time_signed: i64,
    pub value: i64,
    pub spork_hash: UInt256,
    pub signature: Vec<u8>,

    pub chain_id: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="sporks"]
pub struct NewSporkEntity {
    pub identifier: i32,
    pub time_signed: i64,
    pub value: i64,

    pub spork_hash: UInt256,
    pub signature: Vec<u8>,

    pub chain_id: i32,
}

impl Entity for SporkEntity {
    type Type = sporks::dsl::sporks;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        sporks::dsl::sporks
    }
}
