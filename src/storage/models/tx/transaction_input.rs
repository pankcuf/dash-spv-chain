use diesel::{QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::primitives::utxo::UTXO;
use crate::crypto::UInt256;
use crate::schema::transaction_inputs;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;

/// queries:
/// "localAddress.derivationPath.friendRequest == %@"
/// indexation:
/// "transaction.transactionHash.blockHeight": ASC
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct TransactionInputEntity {
    pub id: i32,

    pub local_address_id: Option<i32>,
    pub prev_output_id: Option<i32>,
    pub transaction_id: i32,
    // pub transaction_27: i32,
    // pub transaction_fok: i32,

    pub n: i32,
    pub sequence: i32,
    pub signature: Vec<u8>,
    pub tx_hash: UInt256,

}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="transaction_inputs"]
pub struct NewTransactionInputEntity {
    pub local_address_id: Option<i32>,
    pub prev_output_id: Option<i32>,
    pub transaction_id: i32,
    // pub transaction_27: i32,
    // pub transaction_fok: i32,

    pub n: i32,
    pub sequence: i32,
    pub signature: Vec<u8>,
    pub tx_hash: UInt256,
}

impl Entity for TransactionInputEntity {
    type ID = transaction_inputs::id;
    type ChainId = None;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        transaction_inputs::dsl::transaction_inputs
    }
}

impl TransactionInputEntity {
    pub fn inputs_for_transaction_id(transaction_id: i32, context: &ManagedContext) -> QueryResult<Vec<Self>> {
        Self::read(transaction_inputs::transaction_id.eq(transaction_id), context)
    }

    pub fn outpoint(&self) -> UTXO {
        UTXO { hash: self.tx_hash, n: self.n as u32 }
    }
}
