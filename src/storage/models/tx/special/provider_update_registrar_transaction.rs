use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::{UInt160, UInt256, UInt384};
use crate::schema::provider_update_registrar_transactions;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct ProviderUpdateRegistrarTransactionEntity {
    pub id: i32,
    pub base_id: i32,

    pub local_masternode_id: i32,

    pub provider_mode: i16,
    pub operator_key: UInt384,
    pub provider_registration_transaction_hash: UInt256,
    pub voting_key_hash: UInt160,

    pub payload_signature: Vec<u8>,
    pub script_payout: Vec<u8>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="provider_update_registrar_transactions"]
pub struct NewProviderUpdateRegistrarTransactionEntity {
    pub base_id: i32,

    pub local_masternode_id: i32,

    pub provider_mode: i16,
    pub operator_key: UInt384,
    pub provider_registration_transaction_hash: UInt256,
    pub voting_key_hash: UInt160,

    pub payload_signature: Vec<u8>,
    pub script_payout: Vec<u8>,
}

impl Entity for ProviderUpdateRegistrarTransactionEntity {
    type Type = provider_update_registrar_transactions::dsl::provider_update_registrar_transactions;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        provider_update_registrar_transactions::dsl::provider_update_registrar_transactions
    }
}
