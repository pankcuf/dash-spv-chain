use diesel::{QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::common::ChainType;
use crate::crypto::UInt256;
use crate::schema::invitations;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::Entity;

/// "chain == %@"
/// "blockchainIdentity.uniqueID == %@"

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct InvitationEntity {
    pub id: i32,
    pub link: Option<String>,
    pub name: Option<String>,
    pub tag: Option<String>,
    pub chain_id: i32,
    pub identity_id: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="invitations"]
pub struct NewInvitationEntity {
    pub link: &'static str,
    pub chain_id: i32,
    pub identity_id: i32,
}

impl Entity for InvitationEntity {
    type ID = invitations::id;
    type ChainId = invitations::chain_id;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        invitations::dsl::invitations
    }
}

impl InvitationEntity {
    pub fn get_identity(&self) -> IdentityEntity {
        todo!()
    }

    pub fn count_invitations_for_chain_type(chain_type: ChainType, context: &ManagedContext) -> QueryResult<i64> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain|
                Self::count(invitations::chain_id.eq(chain.id), context))
    }

    pub fn get_by_identity_unique_id(identity_unique_id: &UInt256, context: &ManagedContext) -> QueryResult<InvitationEntity> {
        IdentityEntity::identity_with_unique_id(identity_unique_id, context)
            .and_then(|identity_entity|
                Self::any(invitations::identity_id.eq(identity_entity.id), context))
    }

}
