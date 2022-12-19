use diesel::{BoolExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use crate::crypto::UInt256;
use crate::platform::identity::username_status::UsernameStatus;
use crate::schema::identity_usernames;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::{Entity, last_insert_id};

/// "blockchainIdentity.uniqueID == %@"

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct IdentityUsernameEntity {
    pub id: i32,
    pub domain: String,
    pub salt: UInt256,
    pub status: i16,
    pub string_value: String,
    pub identity_id: i32,
}
#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="identity_usernames"]
pub struct NewIdentityUsernameEntity {
    pub domain: &'static str,
    pub salt: UInt256,
    pub status: i16,
    pub string_value: &'static str,
    pub identity_id: i32,
}

impl Entity for IdentityUsernameEntity {
    type ID = identity_usernames::id;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        identity_usernames::dsl::identity_usernames
    }
}

impl IdentityUsernameEntity {

    pub fn username

    pub fn usernames_with_identity_id(identity_id: i32, context: &ManagedContext) -> QueryResult<Vec<IdentityUsernameEntity>> {
        let predicate = identity_usernames::identity_id.eq(identity_id);
        Self::read(predicate, context)
    }

    pub fn update_with_identity_id(identity_id: i32, username: &String, domain: &String, status: &UsernameStatus, salt: Option<&UInt256>, context: &ManagedContext) -> QueryResult<Self> {
        let values = if let Some(salt) = salt {
            (identity_usernames::status.eq(status.into() as i16),
             identity_usernames::salt.eq(salt))
        } else {
            (identity_usernames::status.eq(status.into() as i16))
        };
        let predicate = identity_usernames::identity_id.eq(identity_id)
            .and(identity_usernames::domain.eq(domain)
                .and(identity_usernames::string_value.eq(username)));
        match Self::update(predicate, values, context) {
            Ok(result) if result == 1 => match last_insert_id(context) {
                Ok(id) => Self::any(identity_usernames::id.eq(id), context),
                Err(err) => Err(err)
            },
            Ok(..) => Err(diesel::result::Error::NotFound),
            Err(err) => panic!("UsernameEntity update error: {}", err)
        }

    }
}
