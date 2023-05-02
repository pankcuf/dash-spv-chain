use diesel::{BoolExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::transaction_outputs;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::account::AccountEntity;
use crate::storage::models::entity::Entity;
use crate::storage::models::tx::transaction::TransactionEntity;
use crate::storage::models::tx::transaction_input::TransactionInputEntity;

/// queries:
/// "txHash == %@ && n == %d"
/// "address == %@"
///
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = transaction_outputs)]
pub struct TransactionOutputEntity {
    pub id: i32,

    pub account_id: Option<i32>,
    pub local_address_id: Option<i32>,
    pub spent_in_input_id: Option<i32>,
    pub transaction_id: i32,
    // pub transaction_27: i32,
    // pub transaction_fok: i32,

    pub address: String,
    pub shapeshift_outbound_address: Option<String>,
    pub n: i32,
    pub value: i64,
    pub script: Vec<u8>,
    pub tx_hash: UInt256,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = transaction_outputs)]
pub struct NewTransactionOutputEntity {
    pub account_id: Option<i32>,
    pub local_address_id: Option<i32>,
    pub spent_in_input_id: Option<i32>,
    pub transaction_id: i32,
    // pub transaction_27: i32,
    // pub transaction_fok: i32,

    pub address: &'static str,
    pub shapeshift_outbound_address: Option<&'static str>,
    pub n: i32,
    pub value: i64,
    pub script: Vec<u8>,
    pub tx_hash: UInt256,
}

struct TransactionOutputAggregate {
    pub output: TransactionOutputEntity,
    pub transaction: TransactionEntity,
    pub spent_in_input: Option<TransactionInputEntity>,
    pub spent_in_transaction: Option<TransactionEntity>,
}

impl Entity for TransactionOutputEntity {
    type ID = transaction_outputs::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         transaction_outputs::dsl::transaction_outputs
    }
}

impl TransactionOutputEntity {

    pub fn get_by_address(address: &Vec<u8>, context: &ManagedContext) -> QueryResult<Vec<TransactionOutputEntity>> {
        Self::read(transaction_outputs::address.eq(address), context)
    }

    pub fn get_by_account_id(account_id: i32, context: &ManagedContext) -> QueryResult<Vec<TransactionOutputEntity>> {
        Self::read(transaction_outputs::account_id.eq(account_id), context)
    }

    pub fn get_by_tx_hash_and_index(tx_hash: &UInt256, index: u32, context: &ManagedContext) -> QueryResult<TransactionOutputEntity> {
        Self::any(transaction_outputs::tx_hash.eq(tx_hash).and(transaction_outputs::n.eq(index)), context)
    }

    pub fn aggregate_outputs(wallet_unique_id: &String, account_number: u32, context: &ManagedContext) -> QueryResult<Vec<TransactionOutputAggregate>> {
        AccountEntity::get_by_wallet_unique_id(wallet_unique_id, account_number as i32, context)
            .and_then(|account_entity| Self::get_by_account_id(account_entity.id, context)
                .map(|outputs| {
                    outputs.iter().filter_map(|&output|
                        TransactionEntity::get_by_id(output.transaction_id, context)
                            .and_then(|transaction|
                                if let Some(input_id) = output.spent_in_input_id {
                                    TransactionInputEntity::get_by_id(input_id, context)
                                        .and_then(|spent_in_input| TransactionEntity::get_by_id(spent_in_input.transaction_id, context)
                                            .and_then(|spent_in_transaction| Ok(TransactionOutputAggregate {
                                                output,
                                                transaction,
                                                spent_in_input: Some(spent_in_input),
                                                spent_in_transaction: Some(spent_in_transaction)
                                            })))
                                } else {
                                    Ok(TransactionOutputAggregate { output, transaction, ..Default::default() })
                                }
                            ).ok())
                        .collect()
                }))
    }

    pub(crate) fn outputs_for_transaction_id(transaction_id: i32, context: &ManagedContext) -> QueryResult<Vec<TransactionOutputEntity>> {
        Self::read(transaction_outputs::transaction_id.eq(transaction_id), context)
    }

    pub(crate) fn spent_in_input(&self, input_id: i32, context: &ManagedContext) -> QueryResult<usize> {
        self.update_with(transaction_outputs::spent_in_input_id.eq(Some(input_id)), context)
    }

}
