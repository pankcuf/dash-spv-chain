use diesel::{BoolExpressionMethods, ExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::common::ChainType;
use crate::crypto::UInt256;
use crate::platform::contract::contract::Contract;
use crate::schema::contracts;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::Entity;

/// "localContractIdentifier == %@ && chain == %@"
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = contracts)]
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
#[diesel(table_name = contracts)]
pub struct NewContractEntity {
    pub state: i16,
    pub local_contract_id: &'static str,
    pub registered_identity_unique_id: Option<UInt256>,
    pub entropy: Option<UInt256>,

    pub chain_id: i32,
    pub creator_id: i32,
}

impl Entity for ContractEntity {
    type ID = contracts::id;
    // type ChainId = contracts::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         contracts::dsl::contracts
    }
}

impl ContractEntity {
    pub fn get_by_local_identifier(local_identifier: &String, chain_type: ChainType, context: &ManagedContext) -> QueryResult<Self> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity| Self::any(contracts::local_contract_id.eq(local_identifier).and(contracts::chain_id.eq(chain_entity.id)), context))
    }

    pub fn update_or_create(contract: &Contract, context: &ManagedContext) -> QueryResult<Self> {
        todo!()
    }
}
