use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::{UInt128, UInt256, UInt768};
use crate::schema::provider_update_service_transactions;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug, Default)]
#[diesel(table_name = provider_update_service_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
#[diesel(belongs_to(LocalMasternodeEntity, foreign_key = local_masternode_id))]
pub struct ProviderUpdateServiceTransactionEntity {
    pub id: i32,
    pub base_id: i32,

    pub local_masternode_id: i32,

    pub ip_address: UInt128,
    pub port: i16,

    pub provider_registration_transaction_hash: UInt256,
    pub payload_signature: UInt768,
    pub script_payout: Vec<u8>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = provider_update_service_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
#[diesel(belongs_to(LocalMasternodeEntity, foreign_key = local_masternode_id))]
pub struct NewProviderUpdateServiceTransactionEntity {
    pub base_id: i32,

    pub local_masternode_id: i32,

    pub ip_address: UInt128,
    pub port: i16,

    pub provider_registration_transaction_hash: UInt256,
    pub payload_signature: UInt768,
    pub script_payout: Vec<u8>,
}

impl Entity for ProviderUpdateServiceTransactionEntity {
    type ID = provider_update_service_transactions::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        // provider_update_service_transactions::dsl::provider_update_service_transactions
    }
}
