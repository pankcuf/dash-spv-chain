use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, QueryResult, QuerySource, Table};
use diesel::associations::HasTable;
use diesel::query_builder::{IntoUpdateTarget, QueryFragment, QueryId};
use diesel::sqlite::Sqlite;
use futures::StreamExt;
use crate::crypto::UInt256;
use crate::schema::friend_requests;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::account::AccountEntity;
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::account::user::UserEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::storage::models::entity::Entity;
use crate::util::big_uint::uint256_add_le;

/// queries:
/// "sourceContact == %@"
/// "destinationContact == %@"
/// "destinationContact.associatedBlockchainIdentity.uniqueID == %@"
/// "sourceContact.associatedBlockchainIdentity.uniqueID == %@"
/// "sourceContact.associatedBlockchainIdentity.uniqueID == %@ && destinationContact.associatedBlockchainIdentity.uniqueID == %@"
/// "derivationPath.publicKeyIdentifier == %@"
/// "sourceContact == %@ && destinationContact.associatedBlockchainIdentity.uniqueID == %@"
/// "destinationContact == %@ && sourceContact.associatedBlockchainIdentity.uniqueID == %@"
/// "(derivationPath.chain == %@)"
/// "(friendshipIdentifier == %@)"
/// "sourceContact == %@ && (SUBQUERY(sourceContact.incomingRequests, $friendRequest, $friendRequest.sourceContact == SELF.destinationContact).@count == 0)"
/// "destinationContact == %@ && (SUBQUERY(destinationContact.outgoingRequests, $friendRequest, $friendRequest.destinationContact == SELF.sourceContact).@count > 0)"
/// indexation:
/// "destinationContact.associatedBlockchainIdentity.dashpayUsername.stringValue"
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct FriendRequestEntity {
    pub id: i32,
    pub source_key_index: i32,
    pub destination_key_index: i32,
    pub derivation_path_id: i32,
    pub timestamp: NaiveDateTime,//i64
    pub friendship_identifier: UInt256,

    pub account_id: i32,
    pub source_contact_id: i32,
    pub destination_contact_id: i32,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="friend_requests"]
pub struct NewFriendRequestEntity {
    pub account_id: i32,
    pub source_key_index: i32,
    pub destination_key_index: i32,
    pub source_contact_id: i32,
    pub destination_contact_id: i32,
    pub derivation_path_id: i32,
    pub timestamp: NaiveDateTime,//i64
    pub friendship_identifier: UInt256,
}

pub struct FriendRequestAggregate {
    pub request: FriendRequestEntity,
    pub user: UserEntity,
    pub identity: IdentityEntity,
    pub context: &'static ManagedContext,
}

pub struct FriendshipAggregate {
    pub account_index: i32,
    pub friendship_identifier: UInt256,
    pub derivation_path: DerivationPathEntity,
    // pub derivation_path_public_key_identifier: String,
    pub destination_identity_unique_id: UInt256,
    pub source_identity_unique_id: UInt256,
    pub context: &'static ManagedContext,
}

impl Entity for FriendRequestEntity {
    type ID = friend_requests::id;
    type ChainId = None;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        friend_requests::dsl::friend_requests
    }
}

impl FriendRequestEntity {

    pub fn get_account(&self, context: &ManagedContext) -> QueryResult<AccountEntity> {
        AccountEntity::get_by_id(self.account_id, context)
    }

    pub fn get_derivation_path(&self, context: &ManagedContext) -> QueryResult<DerivationPathEntity> {
        DerivationPathEntity::get_by_id(self.derivation_path_id, context)
    }

    pub fn get_destination_user(&self, context: &ManagedContext) -> QueryResult<UserEntity> {
        UserEntity::get_by_id(self.destination_contact_id, context)
    }

    pub fn get_source_user(&self, context: &ManagedContext) -> QueryResult<UserEntity> {
        UserEntity::get_by_id(self.source_contact_id, context)
    }

    // (account_index, derivation_path_public_key_identifier, destination_identity_unique_id)
    pub fn aggregate_internals(&self, context: &ManagedContext) -> QueryResult<(i32, DerivationPathEntity, UInt256)> {
        self.get_derivation_path(context)
            .and_then(|derivation_path| self.get_account(context)
                .and_then(|account| self.get_destination_user(context)
                    .and_then(|destination_user| destination_user.get_identity(context)
                        .and_then(|destination_identity| Ok((account.index, derivation_path, destination_identity.unique_id))))))
    }

    pub fn outgoing_requests_for_user_with_id(user_id: i32, context: &ManagedContext) -> QueryResult<Vec<Self>> {
        Self::read(friend_requests::source_contact_id.eq(user_id), context)
    }

    pub fn incoming_requests_for_user_with_id(user_id: i32, context: &ManagedContext) -> QueryResult<Vec<Self>> {
        Self::read(friend_requests::destination_contact_id.eq(user_id), context)
    }

    pub fn between_users_with_identity_ids(source_unique_id: &UInt256, destination_unique_id: &UInt256) -> QueryResult<Self> {
        match (UserEntity::get_by_identity_unique_id(destination_unique_id, context),
               UserEntity::get_by_identity_unique_id(source_unique_id, context)) {
            (Ok(destination_user), Ok(source_user)) =>
                Self::any(
                    friend_requests::destination_contact_id.eq(destination_user.id)
                        .and(friend_requests::source_contact_id.eq(source_user.id)),
                    context),
            _ => Err(diesel::result::Error::NotFound)
        }
    }
    pub fn existing_friend_request_entity_on_friendship_identifier(friendship_identifier: &UInt256, context: &ManagedContext) -> QueryResult<Self> {
        Self::any(friend_requests::friendship_identifier.eq(friendship_identifier), context)
    }

    pub fn existing_friend_request_entity_with_source_identifier(source_identifier: &UInt256, destination_identifier: &UInt256, account_index: u32, context: &ManagedContext) -> QueryResult<Self> {
        let friendship_identifier = Self::friendship_identifier_with_source_identifier(source_identifier, destination_identifier, account_index);
        Self::existing_friend_request_entity_on_friendship_identifier(&friendship_identifier, context)
    }

    pub fn friendship_identifier_with_source_identifier(source_identifier: &UInt256, destination_identifier: &UInt256, account_index: u32) -> UInt256 {
        let mut friendship = UInt256(source_identifier.0.iter().zip(destination_identifier.0).map(|(x, y)| x ^ y).collect());
        // todo: check validity of operations
        if source_identifier > destination_identifier {
            // the destination should always be bigger than the source, otherwise add 1 on the 32nd bit to differenciate them
            friendship = uint256_add_le(friendship, UInt256::from_u32(1 << 31));
        }
        UInt256(friendship.0.iter().zip(UInt256::from_u32(account_index).0).map(|(x, y)| x ^ y).collect())
    }


}
