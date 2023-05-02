use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::coinbase_transactions;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = coinbase_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
pub struct CoinbaseTransactionEntity {
    pub id: i32,
    pub base_id: i32,
    pub height: i32,
    pub merkle_root_mn_list: UInt256,
    pub locked_amount: i64,
}

#[derive(Insertable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = coinbase_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
pub struct NewCoinbaseTransactionEntity {
    pub base_id: i32,
    pub height: i32,
    pub merkle_root_mn_list: UInt256,
    pub locked_amount: i64,
}

impl Entity for CoinbaseTransactionEntity {
    type ID = coinbase_transactions::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        coinbase_transactions::dsl::coinbase_transactions
    }
}
