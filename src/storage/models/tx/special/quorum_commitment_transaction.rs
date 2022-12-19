use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::schema::quorum_commitment_transactions;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct QuorumCommitmentTransactionEntity {
    pub id: i32,
    pub base_id: i32,
    pub quorum_id: i32,
    pub quorum_commitment_height: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="quorum_commitment_transactions"]
pub struct NewQuorumCommitmentTransactionEntity {
    pub base_id: i32,
    pub quorum_id: i32,
    pub quorum_commitment_height: i32,
}

impl Entity for QuorumCommitmentTransactionEntity {
    type Type = quorum_commitment_transactions::dsl::quorum_commitment_transactions;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        quorum_commitment_transactions::dsl::quorum_commitment_transactions
    }
}
