use chrono::NaiveDateTime;
use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::governance_votes;
use crate::storage::models::entity::Entity;

/// queries:
/// "governanceVoteHash.governanceObject = %@"
/// "governanceVoteHash.chain = %@"
/// "(governanceObject == %@) && (governanceVoteHash in %@)"
/// "governanceVoteHash.governanceObject == %@"
/// "governanceVoteHash.governanceVoteHash = %@"
/// (votehash) "governanceObject = %@ && governanceVote == nil"
/// (votehash) "chain == %@ && timestamp > %@"
/// (votehash) "chain == %@ && timestamp > %@ && governanceVote == nil"
/// (votehash) "governanceObject = %@ && governanceVote == nil"
/// (votehash) "governanceVoteHash.governanceObject = %@ && governanceVote != nil",
/// (votehash) "(chain == %@)"
/// indexation:
/// "masternode" ASC
/// (votehash) "governanceVoteHash" ASC
/// (votehash) "timestamp" ASC
/// (votehash) "timestamp" DESC
///
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct GovernanceVoteEntity {
    pub id: i32,
    pub chain_id: i32,
    pub masternode: i32,
    pub masternode_index: i32,
    pub masternode_hash: UInt256,
    pub outcome: i32,
    pub signal: i32,
    pub timestamp_created: NaiveDateTime,
    pub parent_hash: UInt256,
    pub signature: Vec<u8>,

    pub object_id: i32,
    pub vote_hash: UInt256,
    pub vote_timestamp: NaiveDateTime,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="governance_votes"]
pub struct NewGovernanceVoteEntity {
    pub chain_id: i32,
    pub masternode: i32,
    pub masternode_index: i32,
    pub masternode_hash: UInt256,
    pub outcome: i32,
    pub signal: i32,
    pub timestamp_created: NaiveDateTime,
    pub parent_hash: UInt256,
    pub signature: Vec<u8>,

    pub object_id: i32,
    pub vote_hash: UInt256,
    pub vote_timestamp: NaiveDateTime,

}

impl Entity for GovernanceVoteEntity {
    type Type = governance_votes::dsl::governance_votes;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        governance_votes::dsl::governance_votes
    }
}
