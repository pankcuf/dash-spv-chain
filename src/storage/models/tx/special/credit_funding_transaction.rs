use diesel::{ExpressionMethods, QueryDsl, QueryResult, QuerySource, Table, RunQueryDsl};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::{credit_funding_transactions, transactions};
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;
use crate::storage::models::tx::transaction::TransactionEntity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = credit_funding_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
#[diesel(belongs_to(IdentityEntity, foreign_key = registered_identity_id))]
#[diesel(belongs_to(IdentityEntity, foreign_key = topped_up_identity_id))]
pub struct CreditFundingTransactionEntity {
    pub id: i32,
    pub base_id: i32,
    pub registered_identity_id: i32,
    pub topped_up_identity_id: i32,

}

#[derive(Insertable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = credit_funding_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
#[diesel(belongs_to(IdentityEntity, foreign_key = registered_identity_id))]
#[diesel(belongs_to(IdentityEntity, foreign_key = topped_up_identity_id))]
pub struct NewCreditFundingTransactionEntity {
    pub base_id: i32,
    pub registered_identity_id: i32,
    pub topped_up_identity_id: i32,
}

impl Entity for CreditFundingTransactionEntity {
    type ID = credit_funding_transactions::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        credit_funding_transactions::dsl::credit_funding_transactions
    }
}

impl CreditFundingTransactionEntity {
    pub fn get_by_tx_hash(hash: &UInt256, context: &ManagedContext) -> QueryResult<(Self, TransactionEntity)> {
        // Self::any(predicate, context)
        //     .and_then(|cf_tx| TransactionEntity::get_by_id(cf_tx.base_id, context)
        //         .and_then(|tx| Ok((cf_tx, tx))))
        //
        Self::target::<credit_funding_transactions::dsl::credit_funding_transactions>()
            .inner_join(TransactionEntity::target())
            .select((Self::ID, transactions::id))
            .filter(transactions::hash.eq(hash))
            .first(&mut context.connection())


    }
}
