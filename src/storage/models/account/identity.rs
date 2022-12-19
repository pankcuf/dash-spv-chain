use std::iter::Filter;
use std::ops::DerefMut;
use std::slice::Iter;
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, QueryResult, QuerySource, RunQueryDsl, Table};
use diesel::dsl::count;
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::common::ChainType;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::UInt256;
use crate::platform::identity::identity::Identity;
use crate::platform::identity::username_status::UsernameStatus;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::account::AccountEntity;
use crate::storage::models::account::friend_request::{FriendRequestEntity, FriendshipAggregate};
use crate::storage::models::account::identity_key_path::{IdentityKeyPathEntity, NewIdentityKeyPathEntity};
use crate::storage::models::account::identity_username::{IdentityUsernameEntity, NewIdentityUsernameEntity};
use crate::storage::models::account::user::UserEntity;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::{Entity, EntityUpdates, last_insert_id};
use crate::schema;
use crate::schema::identities;
use crate::storage::models::common::derivation_path::DerivationPathEntity;

/// "chain == %@"
/// "uniqueID == %@"
/// "chain == %@ && isLocal == FALSE"
/// "chain == %@ && isLocal == TRUE"
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[table_name="identities"]
pub struct IdentityEntity {
    pub id: i32,
    pub credit_balance: i64,
    pub dashpay_sync_block_hash: UInt256,
    pub is_local: bool,
    pub registration_status: i16,
    pub unique_id: UInt256,
    pub last_checked_incoming_contacts_timestamp: NaiveDateTime,
    pub last_checked_outgoing_contacts_timestamp: NaiveDateTime,
    pub last_checked_profile_timestamp: NaiveDateTime,
    pub last_checked_usernames_timestamp: NaiveDateTime,

    /// Relationships
    pub chain_id: i32,
    pub associated_invitation_id: Option<i32>,
    pub dashpay_username_id: Option<i32>,
    pub matching_user_id: Option<i32>,
    pub registration_funding_id: Option<i32>,

    // pub created_contract_ids: Vec<i32>,
    // pub key_path_ids: Vec<i32>,
    // pub topup_funding_transaction_ids: Vec<i32>,
    // pub username_ids: Vec<i32>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="identities"]
pub struct NewIdentityEntity {
    pub chain_id: i32,
    pub credit_balance: i64,
    pub dashpay_sync_block_hash: UInt256,
    pub is_local: bool,
    pub last_checked_incoming_contacts_timestamp: NaiveDateTime,
    pub last_checked_outgoing_contacts_timestamp: NaiveDateTime,
    pub last_checked_profile_timestamp: NaiveDateTime,
    pub last_checked_usernames_timestamp: NaiveDateTime,
    pub registration_status: i16,
    pub unique_id: UInt256,
}

impl Entity for IdentityEntity {
    type ID = identities::id;
    type ChainId = identities::chain_id;

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        identities::dsl::identities
    }
}

impl IdentityEntity {

    fn add_username_entity(&self, username_entity: IdentityUsernameEntity, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = identities::id.eq(self.id);
        let values = (identities::dashpay_username_id.eq(username_entity.id));
        Self::update(predicate, &values, context)
    }

    pub fn save_new_username(unique_id: &UInt256, username: &String, domain: &String, status: &UsernameStatus, salt: UInt256, context: &ManagedContext) -> QueryResult<usize> {
        Self::identity_with_unique_id(unique_id, context)
            .and_then(|entity|
                IdentityUsernameEntity::create_and_get(&NewIdentityUsernameEntity {
                    domain,
                    salt,
                    status: status.into(),
                    string_value: username,
                    identity_id: entity.id,
                }, context)
                    .and_then(|username_entity|
                        entity.add_username_entity(username_entity, context)))
    }

    pub fn save_username_in_domain(unique_id: &UInt256, username: &String, domain: &String, status: &UsernameStatus, salt: Option<&UInt256>, context: &ManagedContext) -> QueryResult<IdentityUsernameEntity> {
        Self::identity_with_unique_id(unique_id, context)
            .and_then(|entity|
                IdentityUsernameEntity::update_with_identity_id(entity.id, username, domain, status, salt, context))
    }

    pub fn save_username_full_path(unique_id: &UInt256, username_full_path: &String, status: &UsernameStatus, salt: Option<&UInt256>, context: &ManagedContext) -> QueryResult<IdentityUsernameEntity> {
        Self::identity_with_unique_id(unique_id, context)
            .and_then(|entity|
                match IdentityUsernameEntity::usernames_with_identity_id(entity.id, context) {
                    Ok(usernames) if usernames.is_empty() => {
                        println!("no usernames with full path {} for identity with unique_id {}", username_full_path, unique_id);
                        Err(diesel::result::Error::NotFound)
                    },
                    Ok(usernames) => {
                        let usernames_with_full_path = usernames.iter().filter(|u| Identity::full_path_for_username(&u.string_value, &u.domain) == username_full_path).collect::<Vec<_>>();
                        match usernames_with_full_path.len() {
                            1 => {
                                let first = usernames_with_full_path.first().unwrap();
                                IdentityUsernameEntity::update_with_identity_id(entity.id, &first.string_value, &first.domain, status, salt, context)
                            },
                            0 => {
                                println!("no usernames with full path {} for identity with unique_id {}", username_full_path, unique_id);
                                Err(diesel::result::Error::NotFound)
                            },
                            _ => panic!("There should never be more usernames for identity than 1")
                        }
                    },
                    Err(err) => Err(err)
                })
    }

    pub fn delete_identity_for_wallet(unique_id: &UInt256, wallet: &Wallet, context: &ManagedContext) -> QueryResult<usize> {
        Self::identity_with_unique_id(unique_id, context)
            .and_then(|entity|
                FriendRequestEntity::outgoing_requests_for_user_with_id(entity.matching_user_id, context).and_then(|requests| {
                    requests.iter().for_each(|request|
                        match AccountEntity::get_by_id(request.account_id, context) {
                            Ok(account_entity) => {
                                if let Some(account) = wallet.accounts.get(&(account_entity.index as u32)) {
                                    account.remove_incoming_derivation_path_for_friendship_with_identifier(request.friendship_identifier);
                                }
                            },
                            Err(err) => println!("no accounts saved with id {} for identity with unique_id {} error: {}", request.account_id, unique_id, err)
                        }
                    );
                    Self::delete_by_id(entity.id, context)
                }))
    }

    // pub fn delete_identities_for_chain(chain_id: i32, context: &ManagedContext) -> QueryResult<usize> {
    //     let predicate = identities::chain_id.eq(chain_id);
    //     let source = identities::dsl::identities.filter(predicate);
    //     Self::delete(source, context)
    // }

    pub fn identity_with_unique_id(unique_id: &UInt256, context: &ManagedContext) -> QueryResult<IdentityEntity> {
        let predicate = identities::unique_id.eq(unique_id);
        Self::any(predicate, context)
    }

    pub fn load_external_identities(chain_id: i32, context: &ManagedContext) -> QueryResult<Vec<IdentityEntity>> {
        let predicate = identities::chain_id.eq(chain_id)
            .and(identities::is_local.eq(false));
        Self::read(predicate, context)
    }

    pub fn count_local_identities(chain_id: i32, context: &ManagedContext) -> QueryResult<i64> {
        let predicate = identities::chain_id.eq(chain_id)
            .and(identities::is_local.eq(true));
        Self::count(predicate, context)
    }

    pub fn count_local_identities_for_chain_type(chain_type: ChainType, context: &ManagedContext) -> QueryResult<i64> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain|
                Self::count_local_identities(chain.id, context))
    }


    pub fn save_new_remote_identity_key(
        unique_id: &UInt256,
        key_id: i32,
        key_status: i16,
        key_type: i16,
        public_key: Vec<u8>, context: &ManagedContext) -> QueryResult<usize> {
        match Self::identity_with_unique_id(unique_id, context) {
            Ok(identity) => match IdentityKeyPathEntity::count_key_paths_with_key_id(identity.id, key_id, context) {
                Ok(_count @ 0) => IdentityKeyPathEntity::create(&NewIdentityKeyPathEntity {
                    identity_id: identity.id,
                    derivation_path_id: None,
                    key_id,
                    key_status,
                    key_type,
                    public_key,
                    path: vec![]
                }, context),
                _ => Ok(0)
            },
            _ => Ok(0)
        }
    }

    pub fn update_if_needed(identity: &Identity, context: &ManagedContext) -> Result<Vec<String>, diesel::result::Error> {
        let mut changed = false;
        let mut events = Vec::<String>::new();
        let mut updates = ();
        match Self::identity_with_unique_id(&identity.unique_id, context) {
            Ok(entity) => {
                if entity.credit_balance != identity.credit_balance as i64 {
                    updates.append(identities::credit_balance.eq(identity.credit_balance));
                    changed = true;
                    events.push(BlockchainIdentityUpdateEventCreditBalance);
                }
                if entity.registration_status != identity.registration_status.into() {
                    updates.append(identities::registration_status.eq(identity.registration_status.into()));
                    changed = true;
                    events.push(DSBlockchainIdentityUpdateEventRegistration);
                }
                if let Some(sync_block_hash) = identity.dashpay_syncronization_block_hash {
                    if entity.dashpay_sync_block_hash != sync_block_hash {
                        updates.append(identities::dashpay_sync_block_hash.eq(sync_block_hash));
                        changed = true;
                        events.push(DSBlockchainIdentityUpdateEventDashpaySyncronizationBlockHash);
                    }
                }
                if entity.last_checked_usernames_timestamp.timestamp() != identity.last_checked_usernames_timestamp as i64 {
                    updates.append(identities::last_checked_usernames_timestamp.eq(identity.last_checked_usernames_timestamp as i64));
                    changed = true;
                }
                if entity.last_checked_profile_timestamp.timestamp() != identity.last_checked_profile_timestamp as i64 {
                    updates.append(identities::last_checked_profile_timestamp.eq(identity.last_checked_profile_timestamp as i64));
                    changed = true;
                }
                if entity.last_checked_incoming_contacts_timestamp.timestamp() != identity.last_checked_incoming_contacts_timestamp as i64 {
                    updates.append(identities::last_checked_incoming_contacts_timestamp.eq(identity.last_checked_incoming_contacts_timestamp as i64));
                    changed = true;
                }
                if entity.last_checked_outgoing_contacts_timestamp.timestamp() != identity.last_checked_outgoing_contacts_timestamp as i64 {
                    updates.append(identities::last_checked_outgoing_contacts_timestamp.eq(identity.last_checked_outgoing_contacts_timestamp as i64));
                    changed = true;
                }
                if changed {
                    Self::update(ID.eq(entity.id), &updates, context)
                        .and_then(|updated| Ok(events))
                } else {
                    Err(diesel::result::Error::NotFound)
                }
            },
            Err(err) => Err(err)
        }
    }

    // (incoming, outgoing)
    pub fn aggregate_friendship(unique_id: &UInt256, context: &ManagedContext) -> QueryResult<(Vec<FriendshipAggregate>, Vec<FriendshipAggregate>)> {
        match UserEntity::get_by_identity_unique_id(unique_id, context) {
            Ok(user) =>
                user.aggregate_incoming_requests(unique_id, context)
                    .and_then(|incoming| user.aggregate_outgoing_requests(unique_id, context)
                        .and_then(|outgoing| Ok((incoming, outgoing)))),
            Err(err) => Err(err)
        }
    }
}
