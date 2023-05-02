use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::{UInt128, UInt160, UInt256, UInt384};
use crate::schema::provider_registration_transactions;
use crate::storage::models::entity::Entity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = provider_registration_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
#[diesel(belongs_to(LocalMasternodeEntity, foreign_key = local_masternode_id))]
pub struct ProviderRegistrationTransactionEntity {
    pub id: i32,
    pub base_id: i32,

    pub local_masternode_id: i32,

    pub provider_mode: i16,
    pub provider_type: i16,
    pub ip_address: UInt128,
    pub port: i16,
    pub operator_reward: i16,
    pub collateral_outpoint: UInt256,
    pub operator_key: UInt384,
    pub owner_key_hash: UInt160,
    pub voting_key_hash: UInt160,

    pub payload_signature: Vec<u8>,
    pub script_payout: Vec<u8>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = provider_registration_transactions)]
#[diesel(belongs_to(TransactionEntity, foreign_key = base_id))]
#[diesel(belongs_to(LocalMasternodeEntity, foreign_key = local_masternode_id))]
pub struct NewProviderRegistrationTransactionEntity {
    pub base_id: i32,

    pub local_masternode_id: i32,

    pub provider_mode: i16,
    pub provider_type: i16,
    pub ip_address: UInt128,
    pub port: i16,
    pub operator_reward: i16,
    pub collateral_outpoint: UInt256,
    pub operator_key: UInt384,
    pub owner_key_hash: UInt160,
    pub voting_key_hash: UInt160,

    pub payload_signature: Vec<u8>,
    pub script_payout: Vec<u8>,
}

impl Entity for ProviderRegistrationTransactionEntity {
    type ID = provider_registration_transactions::id;
    // type ChainId = ();

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        provider_registration_transactions::dsl::provider_registration_transactions
    }
}

