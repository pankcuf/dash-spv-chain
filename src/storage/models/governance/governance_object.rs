use chrono::NaiveDateTime;
use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::governance_objects;
use crate::storage::models::entity::Entity;

/// queries:
/// "governanceObjectHash.chain = %@"
/// "governanceObjectHash.governanceObjectHash = %@"
/// "governanceObjectHash.chain == %@ && type == %@"
/// indexation:
/// "timestamp" DESC
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = governance_objects)]
pub struct GovernanceObjectEntity {
    pub id: i32,
    pub amount: i64,
    pub collateral_hash: UInt256,
    pub start_epoch: i64,
    pub end_epoch: i64,
    pub revision: i32,
    pub timestamp: NaiveDateTime,
    pub total_votes_count: i64,

    pub object_type: i32,

    pub identifier: String,
    pub payment_address: String,
    pub url: String,

    pub parent_hash: UInt256,
    pub signature: Vec<u8>,

    /// migrated from GovernanceObjectHash
    pub hash: UInt256,
    pub hash_timestamp: NaiveDateTime,

    pub chain_id: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = governance_objects)]
pub struct NewGovernanceObjectEntity {
    pub amount: i64,
    pub start_epoch: i64,
    pub end_epoch: i64,
    pub revision: i32,
    pub timestamp: NaiveDateTime,
    pub total_votes_count: i64,

    pub object_type: i32,

    pub identifier: &'static str,
    pub payment_address: &'static str,
    pub url: &'static str,

    pub collateral_hash: UInt256,
    pub parent_hash: UInt256,
    pub signature: Vec<u8>,

    /// migrated from GovernanceObjectHash
    pub hash: UInt256,
    pub hash_timestamp: NaiveDateTime,

    pub chain_id: i32,
}

impl Entity for GovernanceObjectEntity {
    type ID = governance_objects::id;
    // type ChainId = governance_objects::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        governance_objects::dsl::governance_objects
    }
}
