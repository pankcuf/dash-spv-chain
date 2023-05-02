use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::schema::quorum_commitment_transactions;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = quorum_commitment_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
#[diesel(belongs_to(QuorumEntity, foreign_key = quorum_id))]
pub struct QuorumCommitmentTransactionEntity {
    pub id: i32,
    pub base_id: i32,
    pub quorum_id: i32,
    pub quorum_commitment_height: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = quorum_commitment_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
#[diesel(belongs_to(QuorumEntity, foreign_key = quorum_id))]
pub struct NewQuorumCommitmentTransactionEntity {
    pub base_id: i32,
    pub quorum_id: i32,
    pub quorum_commitment_height: i32,
}

impl Entity for QuorumCommitmentTransactionEntity {
    type ID = quorum_commitment_transactions::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        quorum_commitment_transactions::dsl::quorum_commitment_transactions
    }
}
