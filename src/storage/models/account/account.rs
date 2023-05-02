use diesel::{BoolExpressionMethods, ExpressionMethods, QueryResult, QuerySource, RunQueryDsl, SelectableExpression, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::schema::accounts;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Clone, Debug)]
#[diesel(table_name = accounts)]
#[diesel(belongs_to(ChainEntity, foreign_key = chain_id))]
pub struct AccountEntity {
    pub id: i32,
    pub index: i32,
    pub chain_id: i32,
    pub wallet_unique_id: String,
    // pub derivation_path_ids: Vec<String>,
    // pub friend_request_ids: Vec<String>,
    // pub transaction_output_ids: Vec<String>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = accounts)]
#[diesel(belongs_to(ChainEntity, foreign_key = chain_id))]
pub struct NewAccountEntity {
    pub index: i32,
    pub chain_id: i32,
    pub wallet_unique_id: &'static str,
}

impl Entity for AccountEntity {
    type ID = accounts::id;
    // type ChainId = accounts::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T
        where T: Table + QuerySource,
              T::FromClause: QueryFragment<Sqlite>,
              T::AllColumns: SelectableExpression<T> {
        todo!()
        //        accounts::dsl::accounts
    }
}

impl AccountEntity {

    pub fn get_by_id(account_id: i32, context: &ManagedContext) -> QueryResult<AccountEntity> {
        Self::any(accounts::id.eq(account_id), context)
    }

    pub fn create_account(wallet_unique_id: &String, index: i32, chain_id: i32, context: &ManagedContext) -> QueryResult<usize> {
        let records = NewAccountEntity { index, chain_id, wallet_unique_id };
        Self::create(&records, context)
    }
    pub fn get_by_wallet_unique_id(wallet_unique_id: &String, index: i32, context: &ManagedContext) -> QueryResult<AccountEntity> {
        let predicate = accounts::wallet_unique_id.eq(wallet_unique_id)
            .and(accounts::index.eq(index));
        Self::any(predicate, context)
    }

    pub fn account_for_wallet_unique_id(wallet_unique_id: &String, index: i32, chain_id: i32, context: &ManagedContext) -> Option<AccountEntity> {
        let predicate = accounts::wallet_unique_id.eq(wallet_unique_id)
            .and(accounts::index.eq(index));
        match Self::read(predicate, context) {
            Ok(accounts) if accounts.len() == 1 => accounts.first().map(|a| *a),
            Ok(accounts) if accounts.is_empty() => None,
            Ok(..) => panic!("There can only be one account per index per wallet"),
            Err(err) => {
                println!("{}", err.to_string());
                match Self::create_account(wallet_unique_id, index, chain_id, context) {
                    Ok(_size) => Self::account_for_wallet_unique_id(wallet_unique_id, index, chain_id, context),
                    Err(err) => panic!("Error saving account {}", err.to_string())
                }
            }
        }
    }
}


