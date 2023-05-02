use std::time::SystemTime;
use chrono::NaiveDateTime;
use diesel::{ExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use crate::crypto::byte_util::Random;
use crate::crypto::UInt256;
use crate::schema::users;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::friend_request::{FriendRequestAggregate, FriendRequestEntity, FriendshipAggregate};
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::account::identity_username::IdentityUsernameEntity;
use crate::storage::models::entity::{Entity, EntityUpdates};
use crate::util::time::TimeUtil;

/// "chain == %@"
/// "associatedBlockchainIdentity.uniqueID == %@"
/// "associatedBlockchainIdentity.uniqueID IN %@"
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = users)]
pub struct UserEntity {
    pub id: i32,
    pub chain_id: i32,
    pub identity_id: i32,

    pub local_profile_document_revision: i32,
    pub remote_profile_document_revision: i32,

    pub created_at: NaiveDateTime,//u64
    pub updated_at: NaiveDateTime,//u64

    //"maxLength": 2048
    pub avatar_path: Option<String>,
    //"maxLength": 25
    pub display_name: Option<String>,
    //"maxLength": 140
    pub public_message: Option<String>,

    pub avatar_fingerprint: Option<i64>,
    pub avatar_hash: Option<UInt256>,
    pub document_id: Option<UInt256>,
    pub original_entropy_data: Option<UInt256>,

}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = users)]
pub struct NewUserEntity {
    pub chain_id: i32,
    pub identity_id: i32,
    pub local_profile_document_revision: i32,
    pub remote_profile_document_revision: i32,
    pub created_at: NaiveDateTime,//u64
    pub updated_at: NaiveDateTime,//u64
    //"maxLength": 2048
    pub avatar_path: Option<&'static str>,
    //"maxLength": 25
    pub display_name: Option<&'static str>,
    //"maxLength": 140
    pub public_message: Option<&'static str>,
    pub avatar_fingerprint: Option<i64>,
    pub avatar_hash: Option<UInt256>,
    pub document_id: Option<UInt256>,
    pub original_entropy_data: Option<UInt256>,
}

impl Entity for UserEntity {
    type ID = users::id;
    // type ChainId = users::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        users::dsl::users
    }
}

impl UserEntity {
    pub fn get_identity(&self, context: &ManagedContext) -> QueryResult<IdentityEntity> {
        IdentityEntity::get_by_id(self.identity_id, context)
    }

    pub fn get_by_id(user_id: i32, context: &ManagedContext) -> QueryResult<Self> {
        Self::any(users::id.eq(user_id), context)
    }

    pub fn get_user_and_its_identity_username(unique_id: &UInt256, context: &ManagedContext) -> QueryResult<(Self, IdentityUsernameEntity)> {
        IdentityEntity::identity_with_unique_id(unique_id, context)
            .and_then(|identity| Self::any(users::identity_id.eq(identity.id), context)
                .and_then(|entity| IdentityUsernameEntity::usernames_with_identity_id(identity.id, context)
                    .map(|usernames| (entity, usernames.first().map(|n| *n).unwrap()))))
    }

    pub fn get_by_identity_unique_id(unique_id: &UInt256, context: &ManagedContext) -> QueryResult<Self> {
        IdentityEntity::identity_with_unique_id(unique_id, context)
            .and_then(|identity| Self::any(users::identity_id.eq(identity.id), context))
    }

    fn get_internals(requests: Vec<FriendRequestEntity>, source_identity_unique_id: &UInt256, context: &ManagedContext) -> QueryResult<Vec<FriendshipAggregate>> {
        requests.iter().filter_map(|request|
            match request.aggregate_internals(context) {
                Ok((account_index, derivation_path, destination_identity_unique_id)) =>
                    Some(FriendshipAggregate {
                        account_index,
                        friendship_identifier: request.friendship_identifier,
                        derivation_path,
                        destination_identity_unique_id,
                        source_identity_unique_id: source_identity_unique_id.clone(),
                        context
                    }),
                Err(err) => None
            }).collect()
    }

    pub fn aggregate_incoming_requests(&self, source_identity_unique_id: &UInt256, context: &ManagedContext) -> QueryResult<Vec<FriendshipAggregate>> {
        self.incoming_requests(context)
            .and_then(|requests|
                Self::get_internals(requests, source_identity_unique_id, context))
    }

    pub fn aggregate_outgoing_requests(&self, source_identity_unique_id: &UInt256, context: &ManagedContext) -> QueryResult<Vec<FriendshipAggregate>> {
        self.outgoing_requests(context)
            .and_then(|requests|
                Self::get_internals(requests, source_identity_unique_id, context))
    }

    pub fn incoming_requests(&self, context: &ManagedContext) -> QueryResult<Vec<FriendRequestEntity>> {
        FriendRequestEntity::incoming_requests_for_user_with_id(self.id, context)
    }

    pub fn outgoing_requests(&self, context: &ManagedContext) -> QueryResult<Vec<FriendRequestEntity>> {
        FriendRequestEntity::outgoing_requests_for_user_with_id(self.id, context)
    }

    pub fn incoming_request_aggregate_for_identity_with_unique_id(&self, unique_id: &UInt256, context: &ManagedContext) -> QueryResult<FriendRequestAggregate> {
        //DSFriendRequestEntity *friendRequest =
        // [[matchingDashpayUser.incomingRequests filteredSetUsingPredicate:
        // [NSPredicate predicateWithFormat:@"sourceContact.associatedBlockchainIdentity.uniqueID == %@", uint256_data(otherBlockchainIdentity.uniqueID)]] anyObject];
        self.incoming_requests(context)
            .and_then(|requests|
                match requests
                    .iter()
                    .find_map(|&request| match Self::get_by_id(request.source_contact_id, context) {
                        Ok(source_contact) => match IdentityEntity::get_by_id(source_contact.identity_id, context) {
                            Ok(identity) if identity.unique_id == unique_id => Some(FriendRequestAggregate {identity, request, user: source_contact, context}),
                            _ => None
                        },
                        Err(err) => None
                    }) {
                    Some(aggregate) => Ok(aggregate),
                    None => Err(diesel::result::Error::NotFound)
                })
    }

    pub fn num_of_incoming_requests_for_other_identity_unique_id(&self, unique_id: &UInt256, context: &ManagedContext) -> QueryResult<usize> {
        // [NSPredicate predicateWithFormat:@"sourceContact.associatedBlockchainIdentity.uniqueID == %@", uint256_data(otherBlockchainIdentity.uniqueID)]].count > 0);
        self.incoming_requests(context)
            .and_then(|requests| Ok(requests
                .iter()
                .filter_map(|request|
                    match Self::get_by_id(request.source_contact_id, context) {
                        Ok(source_contact) => match IdentityEntity::get_by_id(source_contact.identity_id, context) {
                            Ok(identity) if identity.unique_id == unique_id => Some(identity),
                            _ => None
                        },
                        _ => None
                    })
                .count()))
            .or(Ok(0))
    }

    pub fn num_of_outgoing_requests_for_other_identity_unique_id(&self, other_identity_id: &UInt256, context: &ManagedContext) -> QueryResult<usize> {
        // [NSPredicate predicateWithFormat:@"destinationContact.associatedBlockchainIdentity.uniqueID == %@", uint256_data(otherBlockchainIdentity.uniqueID)]].count > 0);
        self.outgoing_requests(context)
            .and_then(|requests| Ok(requests
                .iter()
                .filter_map(|request|
                    match Self::get_by_id(request.destination_contact_id, context) {
                        Ok(destination_contact) => match IdentityEntity::get_by_id(destination_contact.identity_id, context) {
                            Ok(identity) if identity.unique_id == other_identity_id => Some(identity),
                            _ => None
                        },
                        _ => None
                    })
                .count()))
            .or(Ok(0))
    }

    pub fn update_with_display_name(&self, display_name: String, context: &ManagedContext) -> QueryResult<usize> {
        let mut values = users::display_name.eq(display_name);
        self.update_with(values, context)
    }

    pub fn update_with_public_message(&self, public_message: String, context: &ManagedContext) -> QueryResult<usize> {
        let mut values = users::public_message.eq(public_message);
        self.update_with(values, context)
    }

    pub fn update_with_public_avatar_url(&self, avatar_path: String, context: &ManagedContext) -> QueryResult<usize> {
        let mut values = users::avatar_path.eq(avatar_path);
        self.update_with(values, context)
    }

    pub fn update_with_display_name_and_public_message(&self, display_name: String, public_message: String, context: &ManagedContext) -> QueryResult<usize> {
        let mut values = (
            users::display_name.eq(display_name),
            users::public_message.eq(public_message)
        );
        self.update_with(values, context)
    }

    pub fn update_with_display_name_and_public_message_and_avatar_path(&self, display_name: String, public_message: String, avatar_path: String, context: &ManagedContext) -> QueryResult<usize> {
        let mut values = (
            users::display_name.eq(display_name),
            users::public_message.eq(public_message),
            users::avatar_path.eq(avatar_path)
        );
        self.update_with(values, context)
    }

    pub fn update_with_display_name_and_public_message_and_avatar_path_and_hash_and_fingerprint(&self, display_name: String, public_message: String, avatar_path: String, avatar_hash: UInt256, avatar_fingerprint: u64, context: &ManagedContext) -> QueryResult<usize> {
        let mut values = (
            users::display_name.eq(display_name),
            users::public_message.eq(public_message),
            users::avatar_path.eq(avatar_path),
            users::avatar_hash.eq(avatar_hash),
            users::avatar_fingerprint.eq(avatar_fingerprint)
        );
        self.update_with(values, context)
    }

    pub fn update_with_avatar_path_and_hash_and_fingerprint(&self, avatar_path: String, avatar_hash: UInt256, avatar_fingerprint: u64, context: &ManagedContext) -> QueryResult<usize> {
        let mut values = (
            users::avatar_path.eq(avatar_path),
            users::avatar_hash.eq(avatar_hash),
            users::avatar_fingerprint.eq(avatar_fingerprint)
        );
        self.update_with(values, context)
    }
    pub fn update_remote_profile_revision(&self, revision: i32, context: &ManagedContext) -> QueryResult<usize> {
        let values = users::remote_profile_document_revision.eq(revision);
        Self::update(users::id.eq(self.id), &values, context)
    }

    pub fn update_revision(&self, context: &ManagedContext) -> QueryResult<i32> {
        if self.local_profile_document_revision > self.remote_profile_document_revision {
            let new_revision = self.remote_profile_document_revision + 1;
            let values = users::local_profile_document_revision.eq(new_revision);
            match Self::update(users::id.eq(self.id), &values, context) {
                Ok(usize) => Ok(new_revision),
                Err(err) => Err(err)
            }
        } else {
            Ok(self.local_profile_document_revision)
        }

    }

    fn update_with<T, V>(&self, mut values: V, context: &ManagedContext) -> QueryResult<usize>
        where T: Table,
              V: AsChangeset<Target = T> {
        values.append(users::updated_at.eq(SystemTime::seconds_since_1970() * 1000));
        values.append(users::local_profile_document_revision.eq(self.local_profile_document_revision + 1));
        if self.remote_profile_document_revision == 0 {
            values.append(users::created_at.eq(SystemTime::seconds_since_1970() * 1000));
            if self.original_entropy_data.is_none() {
                values.append(users::original_entropy_data.eq(UInt256::random()));
            }
        }
        Self::update(users::id.eq(self.id), &values, context)
    }
}
