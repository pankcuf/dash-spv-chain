use diesel::{QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::schema::contracts;
use crate::storage::models::entity::Entity;

/// "localContractIdentifier == %@ && chain == %@"
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct ContractEntity {
    pub id: i32,
    pub state: i16,
    pub local_contract_id: String,
    pub registered_identity_unique_id: Option<UInt256>,
    pub entropy: Option<UInt256>,

    pub chain_id: i32,
    pub creator_id: i32, // IdentityEntity
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="contracts"]
pub struct NewContractEntity {
    pub state: i16,
    pub local_contract_id: &'static str,
    pub registered_identity_unique_id: Option<UInt256>,
    pub entropy: Option<UInt256>,

    pub chain_id: i32,
    pub creator_id: i32,
}

impl Entity for ContractEntity {
    type Type = contracts::dsl::contracts;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        contracts::dsl::contracts
    }
}
