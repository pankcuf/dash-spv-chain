use diesel::{QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::derivation::derivation_path::IDerivationPath;
use crate::schema::derivation_paths;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::entity::Entity;
use crate::storage::models::tx::transaction_input::TransactionInputEntity;
use crate::storage::models::tx::transaction_output::TransactionOutputEntity;

/// "(chain == %@)"
/// "publicKeyIdentifier == %@ && chain == %@"
///
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct DerivationPathEntity {
    pub id: i32,
    pub derivation_path: Vec<u8>,
    pub sync_block_height: i32,
    pub public_key_identifier: String,

    pub chain_id: i32,
    pub account_id: Option<i32>,
    pub friend_request_id: Option<i32>,
    // pub address_ids: Vec<i32>,
    // pub identity_key_path_ids: Vec<i32>,
}


#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="derivation_paths"]
pub struct NewDerivationPathEntity {
    pub derivation_path: Vec<u8>,
    pub sync_block_height: i32,
    pub public_key_identifier: &'static str,

    pub chain_id: i32,
    pub account_id: Option<i32>,
    pub friend_request_id: Option<i32>,
    pub address_ids: Vec<i32>,
    pub identity_key_path_ids: Vec<i32>,
}

impl Entity for DerivationPathEntity {
    type ID = derivation_paths::id;
    type ChainId = derivation_paths::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        derivation_paths::dsl::derivation_paths
    }
}

impl DerivationPathEntity {
    pub fn derivation_path_entity_matching_derivation_path(path: &dyn IDerivationPath, context: &ManagedContext) -> QueryResult<DerivationPathEntity> {
        todo!()
    }

    pub fn get_addresses(&self, context: &ManagedContext) -> QueryResult<Vec<AddressEntity>> {
        AddressEntity::get_by_derivation_path_id(self.id, context)
    }

    pub fn derivation_path_entity_matching_derivation_path_with_addresses(path: &dyn IDerivationPath, context: &ManagedContext) -> QueryResult<(DerivationPathEntity, Vec<AddressEntity>, Vec<TransactionInputEntity>, Vec<TransactionOutputEntity>)> {
        todo!()
    }

    fn get(context: &ManagedContext) -> QueryResult<>
    let data = users.inner_join(posts)
    .select((name, title))
    .load(&connection);

}
