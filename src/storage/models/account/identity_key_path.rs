use std::ops::DerefMut;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryResult, QuerySource, RunQueryDsl, Table};
use diesel::dsl::count;
use diesel::query_builder::QueryFragment;
use diesel::query_dsl::methods::SelectDsl;
use diesel::sqlite::Sqlite;
use crate::schema::identity_key_paths;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;

/// queries:
/// "blockchainIdentity == %@ && derivationPath == %@ && path == %@"
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct IdentityKeyPathEntity {
    pub id: i32,
    pub key_id: i32,
    pub key_status: i16,
    pub key_type: i16,
    pub public_key: Vec<u8>, //bls: u384 ecdsa: u256
    pub path: Vec<u8>,

    pub identity_id: i32,
    pub derivation_path_id: Option<i32>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="identity_key_paths"]
pub struct NewIdentityKeyPathEntity {
    pub key_id: i32,
    pub key_status: i16,
    pub key_type: i16,
    pub public_key: Vec<u8>, //bls: u384 ecdsa: u256
    pub path: Vec<u8>,
    pub identity_id: i32,
    pub derivation_path_id: Option<i32>,
}

impl Entity for IdentityKeyPathEntity {
    type ID = identity_key_paths::id;
    type ChainId = None;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        identity_key_paths::dsl::identity_key_paths
    }
}

impl IdentityKeyPathEntity {

    pub fn count_key_paths_for(identity_id: i32, derivation_path_id: i32, path: &Vec<u8>, context: &ManagedContext) -> QueryResult<i64> {
        let predicate = identity_key_paths::identity_id.eq(identity_id)
            .and(identity_key_paths::derivation_path_id.eq(Some(derivation_path_id)))
            .and(identity_key_paths::path.eq(path));
        Self::count(predicate, context)
    }

    pub fn count_key_paths_with_key_id(identity_id: i32, key_id: i32, context: &ManagedContext) -> QueryResult<i64> {
        let predicate = identity_key_paths::identity_id.eq(identity_id)
            .and(identity_key_paths::key_id.eq(key_id));
        Self::count(predicate, context)
    }

    pub fn get_by_identity_id_and_path(identity_id: i32, derivation_path_id: i32, path: &Vec<u8>, context: &ManagedContext) -> QueryResult<IdentityKeyPathEntity> {
        let predicate = identity_key_paths::identity_id.eq(identity_id)
            .and(identity_key_paths::derivation_path_id.eq(Some(derivation_path_id)))
            .and(identity_key_paths::path.eq(path));
        Self::any(predicate, context)
    }

    pub fn get_by_identity_id_and_key_id(identity_id: i32, key_id: i32, context: &ManagedContext) -> QueryResult<IdentityKeyPathEntity> {
        let predicate = identity_key_paths::identity_id.eq(identity_id)
            .and(identity_key_paths::derivation_path_id.eq(None))
            .and(identity_key_paths::key_id.eq(key_id));
        Self::any(predicate, context)
    }

    pub fn update_key_status(&self, key_status: i32, context: &ManagedContext) -> QueryResult<usize> {
        Self::update(ID.eq(self.id), (identity_key_paths::key_status.eq(key_status)), context)
    }
}
