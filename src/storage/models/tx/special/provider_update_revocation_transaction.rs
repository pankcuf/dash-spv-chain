use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::{UInt256, UInt768};
use crate::schema::provider_update_revocation_transactions;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct ProviderUpdateRevocationTransactionEntity {
    pub id: i32,
    pub base_id: i32,
    pub local_masternode_id: i32,

    pub reason: i16,
    pub provider_registration_transaction_hash: UInt256,
    pub payload_signature: UInt768,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="provider_update_revocation_transactions"]
pub struct NewProviderUpdateRevocationTransactionEntity {
    pub base_id: i32,
    pub local_masternode_id: i32,

    pub reason: i16,
    pub provider_registration_transaction_hash: UInt256,
    pub payload_signature: UInt768,
}

impl Entity for ProviderUpdateRevocationTransactionEntity {
    type Type = provider_update_revocation_transactions::dsl::provider_update_revocation_transactions;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        provider_update_revocation_transactions::dsl::provider_update_revocation_transactions
    }
}
