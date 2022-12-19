use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::coinbase_transactions;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct CoinbaseTransactionEntity {
    pub id: i32,
    pub base_id: i32,
    pub height: i32,
    pub merkle_root_mn_list: UInt256,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="coinbase_transactions"]
pub struct NewCoinbaseTransactionEntity {
    pub base_id: i32,
    pub height: i32,
    pub merkle_root_mn_list: UInt256,
}

impl Entity for CoinbaseTransactionEntity {
    type Type = coinbase_transactions::dsl::coinbase_transactions;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        coinbase_transactions::dsl::coinbase_transactions
    }
}
