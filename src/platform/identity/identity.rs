use std::cmp;
use std::collections::{HashMap, HashSet};
use std::fmt::format;
use std::task::Context;
use std::time::{SystemTime, UNIX_EPOCH};
use bitcoin_hashes::{Hash, sha256d};
use chrono::NaiveDateTime;
use diesel::QueryResult;
use futures::TryFutureExt;
use libp2p::futures::StreamExt;
use crate::chain::block::BLOCK_UNKNOWN_HEIGHT;
use crate::chain::chain::Chain;
use crate::chain::dispatch_context::{DispatchContext, DispatchContextType, DispatchTime};
use crate::chain::extension::accounts::Accounts;
use crate::chain::extension::identities::Identities;
use crate::chain::network::peer::HOUR_TIME_INTERVAL;
use crate::chain::options::sync_type::SyncType;
use crate::chain::params::TX_UNCONFIRMED;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::tx::transaction_type::TransactionType;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::extension::identities::WalletIdentities;
use crate::chain::wallet::wallet::Wallet;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, AsBytesVec, Random, Zeroable};
use crate::crypto::UInt256;
use crate::crypto::primitives::utxo::UTXO;
use crate::dapi;
use crate::dapi::networking::platform;
use crate::dapi::networking::platform::stored_message::StoredMessage;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::derivation_path::{BIP32_HARD, IDerivationPath};
use crate::derivation::uint256_index_path::{IIndexPath, IndexPath};
use crate::keychain::keychain::Keychain;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::notifications::{Notification, NotificationCenter};
use crate::platform::base::serializable_object::{SerializableKey, SerializableValue};
use crate::platform::contract::contract::Contract;
use crate::platform::contract::contract_state::ContractState;
use crate::platform::document;
use crate::platform::document::{Document, Protocol};
use crate::platform::document::document::DocumentValue;
use crate::platform::document::protocol::TableName;
use crate::platform::identity::contact_request::{ContactRequest, ContactRequestJson};
use crate::platform::identity::friendship_status::FriendshipStatus;
use crate::platform::identity::invitation::Invitation;
use crate::platform::identity::key_dictionary::KeyDictionary;
use crate::platform::identity::key_status::KeyStatus;
use crate::platform::identity::monitor_options::MonitorOptions;
use crate::platform::identity::potential_contact::PotentialContact;
use crate::platform::identity::potential_one_way_friendship::PotentialOneWayFriendship;
use crate::platform::identity::query_step::QueryStep;
use crate::platform::identity::registration_status::RegistrationStatus;
use crate::platform::identity::registration_step::RegistrationStep;
use crate::platform::identity::retry_delay_type::RetryDelayType;
use crate::platform::identity::transient_user::TransientUser;
use crate::platform::identity::username_status::UsernameStatus;
use crate::platform::platform::Platform;
use crate::platform::transition::document_transition::DocumentTransition;
use crate::platform::transition::identity_registration_transition::IdentityRegistrationTransition;
use crate::platform::transition::transition::{ITransition, Transition};
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::manager::managed_context_type::ManagedContextType;
use crate::storage::models::account::friend_request::{FriendRequestAggregate, FriendRequestEntity};
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::account::identity_key_path::{IdentityKeyPathEntity, NewIdentityKeyPathEntity};
use crate::storage::models::account::identity_username::IdentityUsernameEntity;
use crate::storage::models::account::invitation::InvitationEntity;
use crate::storage::models::account::user::UserEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::storage::models::entity::Entity;
use crate::util::base58;
use crate::util::time::TimeUtil;

pub const BLOCKCHAIN_USERNAME_STATUS: &str = "BLOCKCHAIN_USERNAME_STATUS";
pub const BLOCKCHAIN_USERNAME_PROPER: &str = "BLOCKCHAIN_USERNAME_PROPER";
pub const BLOCKCHAIN_USERNAME_DOMAIN: &str = "BLOCKCHAIN_USERNAME_DOMAIN";
pub const BLOCKCHAIN_USERNAME_SALT: &str = "BLOCKCHAIN_USERNAME_SALT";

pub const QUERY_WITH_NO_ACTIVE_KEYS: &str = "Attempt to query DAPs for blockchain identity with no active keys";
pub const DPNS_CONTRACT_NOT_REGISTERED: &str = "DPNS Contract is not yet registered on network";
pub const FETCH_USERNAMES_FAILED: &str = "Fail to fetch usernames";
pub const REGISTER_USERNAMES_FAILED: &str = "Fail to register usernames";
pub const CREDIT_FUNDING_TRANSACTION_NOT_MINED: &str = "The registration credit funding transaction has not been mined yet and has no instant send lock";
pub const NO_IDENTITY_RETURNED: &str = "Platform returned no identity when one was expected";


pub const BLOCKCHAIN_USER_UNIQUE_IDENTIFIER_KEY: &str = "BLOCKCHAIN_USER_UNIQUE_IDENTIFIER_KEY";
pub const DEFAULT_SIGNING_ALGORITHM: KeyType = KeyType::ECDSA;
pub const DEFAULT_FETCH_IDENTITY_RETRY_COUNT: u32 = 5;
pub const DEFAULT_FETCH_USERNAMES_RETRY_COUNT: u32 = 5;
pub const DEFAULT_FETCH_PROFILE_RETRY_COUNT: u32 = 5;

pub const DEFAULT_CONTACT_REQUEST_FETCH_RETRIES: u32 = 5;

enum UsernameInfoKind {
    UsernameStatus(&'static UsernameStatus),
    UsernameSalt(&'static UInt256),
    UsernameProper(&'static String),
    UsernameDomain(&'static String),
}

enum KeyInfoDictionaryValue {
    Key(&'static dyn IKey),
    KeyType(&'static KeyType),
}

enum ContractDictionaryValue {
    Id(&'static Vec<u8>),
    Documents(&'static HashMap<String, dyn SerializableValue>)
}

enum ProfileDictionaryValue {
    Balance(u64)
}

impl SerializableValue for UsernameInfoKind {
    fn as_data(&self) -> &[u8] {
        match self {
            UsernameInfoKind::UsernameDomain(domain) => domain.as_data(),
            UsernameInfoKind::UsernameStatus(status) => status.as_data(),
            UsernameInfoKind::UsernameSalt(salt) => salt.as_data(),
            UsernameInfoKind::UsernameProper(proper) => proper.as_data(),
        }
    }
}

enum PreorderDictionaryKey {
    SaltedDomainHash
}

enum DataDictionaryKey {
    Label,
    NormalizedLabel,
    NormalizedParentDomainName,
    PreorderSalt,
    Records,
    SubdomainRules
}

enum Records {
    DashUniqueIdentityId(&'static UInt256),
    Timestamp(&'static NaiveDateTime),
}

enum SubdomainRules {
    AllowSubdomains(bool),
}


enum ContractDictionaryKey {
    Id,
    Documents
}

enum ProfileDictionaryKey {
    Balance
}
enum ProfileDataDictionaryKey {
    UpdatedAt,
    CreatedAt,
    Revision,
    PublicMessage,
    AvatarUrl,
    AvatarFingerprint,
    AvatarHash,
    DisplayName,
}

impl SerializableKey for ProfileDataDictionaryKey {
    fn as_str(&self) -> &str {
        match self {
            ProfileDataDictionaryKey::UpdatedAt => "$updatedAt",
            ProfileDataDictionaryKey::CreatedAt => "$createdAt",
            ProfileDataDictionaryKey::Revision => "$revision",
            ProfileDataDictionaryKey::PublicMessage => "publicMessage",
            ProfileDataDictionaryKey::AvatarUrl => "avatarUrl",
            ProfileDataDictionaryKey::AvatarFingerprint => "avatarFingerprint",
            ProfileDataDictionaryKey::AvatarHash => "avatarHash",
            ProfileDataDictionaryKey::DisplayName => "displayName",
        }
    }
}

impl SerializableKey for PreorderDictionaryKey {
    fn as_str(&self) -> &str {
        match self {
            PreorderDictionaryKey::SaltedDomainHash => "saltedDomainHash",
        }
    }
}

impl SerializableKey for ProfileDictionaryKey {
    fn as_str(&self) -> &str {
        match self {
            ProfileDictionaryKey::Balance => "balance",
        }
    }
}

impl SerializableKey for ContractDictionaryKey {
    fn as_str(&self) -> &str {
        match self {
            ContractDictionaryKey::Documents => "documents",
            ContractDictionaryKey::Id => "$id",
        }
    }
}

impl SerializableKey for DataDictionaryKey {
    fn as_str(&self) -> &str {
        match self {
            DataDictionaryKey::Label => "label",
            DataDictionaryKey::NormalizedLabel => "normalizedLabel",
            DataDictionaryKey::NormalizedParentDomainName => "normalizedParentDomainName",
            DataDictionaryKey::PreorderSalt => "preorderSalt",
            DataDictionaryKey::Records => "records",
            DataDictionaryKey::SubdomainRules => "subdomainRules",
        }
    }
}

impl SerializableValue for ProfileDictionaryValue {
    fn as_data(&self) -> &[u8] {
        match self {
            ProfileDictionaryValue::Balance(value) => value.to_le_bytes().as_bytes(),
        }
    }
}

impl SerializableValue for ContractDictionaryValue {
    fn as_data(&self) -> &[u8] {
        match self {
            // todo: real serialization
            ContractDictionaryValue::Documents(_dict) => &[0u8; 0],
            ContractDictionaryValue::Id(id) => id.as_bytes()
        }
    }
}

impl SerializableValue for Records {
    fn as_data(&self) -> &[u8] {
        match self {
            Records::DashUniqueIdentityId(id) => id.as_bytes(),
            Records::Timestamp(date_time) => date_time.timestamp().to_le_bytes().as_bytes()
            // ("records", HashMap::from([("dashUniqueIdentityId", self.unique_id)])),
        }
    }
}
impl SerializableValue for SubdomainRules {
    fn as_data(&self) -> &[u8] {
        match self {
            SubdomainRules::AllowSubdomains(allow) => allow.as_bytes(),
            // HashMap::from([("allowSubdomains", false)]
        }
    }
}

pub struct Identity {

    /// This is the unique identifier representing the blockchain identity.
    /// It is derived from the credit funding transaction credit burn UTXO (as of dpp v10).
    /// Returned as a 256 bit number
    pub unique_id: UInt256,

    /// This is the unique identifier representing the blockchain identity.
    /// It is derived from the credit funding transaction credit burn UTXO (as of dpp v10).
    /// Returned as a base 58 string of a 256 bit number
    //pub NSString *uniqueIdString;

    /*! @brief This is the unique identifier representing the blockchain identity. It is derived from the credit funding transaction credit burn UTXO (as of dpp v10). Returned as a NSData of a 256 bit number */
    // pub NSData *uniqueIDData;

    /// This is the outpoint of the registration credit funding transaction.
    /// It is used to determine the unique ID by double SHA256 its value.
    /// Returned as a UTXO { .hash , .n }
    pub locked_outpoint: Option<&'static UTXO>,

    /// This is if the blockchain identity is present in wallets or not.
    /// If this is false then the blockchain identity is known for example from being a dashpay friend.
    pub is_local: bool,

    /// This is if the blockchain identity is made for being an invitation.
    /// All invitations should be marked as non local as well.
    pub is_outgoing_invitation: bool,

    /// This is if the blockchain identity is made from an invitation we received.
    pub is_from_incoming_invitation: bool,

    /// This is TRUE if the blockchain identity is an effemeral identity returned when searching.
    pub is_transient: bool,

    /// This is TRUE only if the blockchain identity is contained within a wallet.
    /// It could be in a cleanup phase where it was removed from the wallet but still being help in memory by callbacks.
    pub is_active: bool,

    /// This references transient Dashpay user info if on a transient blockchain identity.
    pub transient_dashpay_user: Option<&'static TransientUser>,

    // pub DSBlockchainIdentityRegistrationStep stepsCompleted;

    /// This is the wallet holding the blockchain identity.
    /// There should always be a wallet associated to a blockchain identity if the blockchain
    /// identity is local, but never if it is not.
    pub wallet: Option<&'static Wallet>,

    /// This is invitation that is identity originated from.
    pub associated_invitation: Option<&'static Invitation>,

    /// This is the index of the blockchain identity in the wallet.
    /// The index is the top derivation used to derive an extended set of keys for the identity.
    /// No two local blockchain identities should be allowed to have the same index in a wallet.
    /// For example m/.../.../.../index/key */
    pub index: u32,

    /// Related to DPNS. This is the list of usernames that are associated to the identity in the domain "dash".
    /// These usernames however might not yet be registered or might be invalid.
    /// This can be used in tandem with the status_of_username: method
    pub dashpay_usernames: Vec<String>,

    /// Related to DPNS. This is the list of usernames with their .dash domain that are associated to the identity in the domain "dash".
    /// These usernames however might not yet be registered or might be invalid.
    /// This can be used in tandem with the status_of_username: method
    pub dashpay_username_full_paths: Vec<String>,

    /// Related to DPNS. This is current and most likely username associated to the identity.
    /// It is not necessarily registered yet on L2 however so its state should be determined with the status_of_username: method
    /// @discussion There are situations where this is nil as it is not yet known or if no username has yet been set.
    pub current_dashpay_username: String,

    /// Related to registering the identity. This is the address used to fund the registration of the identity.
    /// Dash sent to this address in the special credit funding transaction will be converted to L2 credits
    pub registration_funding_address: String,

    /// The known balance in credits of the identity
    pub credit_balance: u64,

    /// The number of registered active keys that the blockchain identity has
    pub active_key_count: u32,

    /// The number of all keys that the blockchain identity has, registered, in registration, or inactive
    pub total_key_count: u32,

    /// This is the transaction on L1 that has an output that is used to fund the creation of this blockchain identity.
    /// @discussion There are situations where this is nil as it is not yet known;
    /// if the blockchain identity is being retrieved from L2 or if we are resyncing the chain.
    pub registration_credit_funding_transaction: Option<&'static CreditFundingTransaction>,

    /// This is the hash of the transaction on L1 that has an output that is used to fund the creation of this blockchain identity.
    /// @discussion There are situations where this is nil as it is not yet known;
    /// if the blockchain identity is being retrieved from L2 or if we are resyncing the chain.
    pub registration_credit_funding_transaction_hash: UInt256,

    /*! @brief In our system a contact is a vue on a blockchain identity for Dashpay. A blockchain identity is therefore represented by a contact that will have relationships in the system. This is in the default backgroundContext. */
    // pub DSDashpayUserEntity *matchingDashpayUserInViewContext;

    /// This is the status of the registration of the identity. It starts off in an initial status, and ends in a confirmed status
    pub registration_status: RegistrationStatus,

    /*! @brief This is the localized status of the registration of the identity returned as a string. It starts off in an initial status, and ends in a confirmed status */
    // pub NSString *localizedRegistrationStatusString;

    /// This is a convenience method that checks to see if registrationStatus is confirmed
    pub is_registered: bool,

    /// This is a convenience factory to quickly make dashpay documents
    pub dashpay_document_factory: Option<&'static document::Factory>,

    /// This is a convenience factory to quickly make dpns documents
    pub dpns_document_factory: Option<&'static document::Factory>,

    /// DashpaySyncronizationBlock represents the last L1 block height for which Dashpay would be synchronized,
    /// if this isn't at the end of the chain then we need to query L2 to make sure we don't need to update our bloom filter
    pub dashpay_syncronization_block_height: u32,

    /// DashpaySyncronizationBlock represents the last L1 block hash for which Dashpay would be synchronized
    pub dashpay_syncronization_block_hash: Option<&'static UInt256>,

    /// Dashpay

    /// This is a helper to easily get the avatar path of the matching dashpay user.
    pub avatar_path: Option<String>,

    /// This is a helper to easily get the avatar fingerprint of the matching dashpay user.
    pub avatar_fingerprint: Option<Vec<u8>>,

    /// This is a helper to easily get the avatar hash of the matching dashpay user.
    pub avatar_hash: Option<Vec<u8>>,

    /// This is a helper to easily get the display name of the matching dashpay user.
    pub display_name: Option<String>,

    /// This is a helper to easily get the public message of the matching dashpay user. */
    pub public_message: Option<String>,

    /// This is a helper to easily get the last time the profile was updated of the matching dashpay user.
    pub dashpay_profile_updated_at: u64,

    /// This is a helper to easily get the creation time of the profile of the matching dashpay user.
    pub dashpay_profile_created_at: u64,


    username_statuses: HashMap<String, HashMap<String, UsernameInfoKind>>,
    current_main_key_index: u32,
    current_main_key_type: KeyType,
    keys_created: u32,
    key_info_dictionaries: HashMap<u32, HashMap<KeyDictionary, dyn SerializableValue>>,
    username_salts: HashMap<String, UInt256>,
    chain: &'static Chain,

    internal_registration_funding_private_key: Option<&'static ECDSAKey>,
    dispatch_context: DispatchContext,

    pub last_checked_usernames_timestamp: u64,
    pub last_checked_profile_timestamp: u64,
    pub last_checked_incoming_contacts_timestamp: u64,
    pub last_checked_outgoing_contacts_timestamp: u64

}

impl Identity {
    pub fn init_with(unique_id: UInt256, is_transient: bool, chain: &Chain) -> Self {
        // this is the initialization of a non local blockchain identity
        assert_ne!(unique_id, UInt256::MIN, "unique_id must not be null");
        Self {
            unique_id,
            is_local: false,
            is_transient,
            current_main_key_type: KeyType::ECDSA,
            registration_status: RegistrationStatus::Registered,
            is_registered: false,
            chain,
            dispatch_context: DispatchContext::new(DispatchContextType::Identity),
            ..Default::default()
        }
    }

    pub fn init_at(index: u32, wallet: &Wallet) -> Self {
        Self {
            wallet: Some(wallet),
            is_local: true,
            is_outgoing_invitation: false,
            is_transient: false,
            keys_created: 0,
            current_main_key_index: 0,
            current_main_key_type: KeyType::ECDSA,
            index,
            username_statuses: HashMap::new(),
            key_info_dictionaries: HashMap::new(),
            registration_status: RegistrationStatus::Unknown,
            username_salts: HashMap::new(),
            chain: wallet.chain,
            dispatch_context: DispatchContext::new(DispatchContextType::Identity),
            ..Default::default()
        }
    }

    pub fn init_at_with_unique_id(index: u32, unique_id: UInt256, wallet: &Wallet) -> Self {
        let mut s = Self::init_at(index, wallet);
        s.unique_id = unique_id;
        s
    }

    pub fn init_at_with_locked_outpoint(index: u32, locked_outpoint: &UTXO, wallet: &Wallet) -> Self {
        let mut s = Self::init_at(index, wallet);
        s.locked_outpoint = Some(locked_outpoint);
        let mut writer = Vec::<u8>::new();
        locked_outpoint.enc(writer);
        s.unique_id = UInt256(sha256d::Hash::hash(&writer).into_inner());
        s
    }

    pub fn init_at_with_locked_outpoint_and_entity(index: u32, locked_outpoint: &UTXO, wallet: &Wallet, entity: &IdentityEntity) -> Self {
        let mut s = Self::init_at_with_locked_outpoint(index, locked_outpoint, wallet);
        s.apply_identity_entity(entity);
        s
    }

    pub fn init_at_with_locked_outpoint_and_entity_and_invitation(index: u32, locked_outpoint: &UTXO, wallet: &Wallet, entity: &IdentityEntity, invitation: &Invitation) -> Self {
        let mut s = Self::init_at_with_locked_outpoint(index, locked_outpoint, wallet);
        s.set_associated_invitation(invitation);
        s.apply_identity_entity(entity);
        s
    }


    pub fn init_at_with_credit_funding_transaction(index: u32, transaction: &CreditFundingTransaction, wallet: &Wallet) -> Option<Self> {
        // if transaction.r#type() != TransactionType::CreditFunding {
        //     return None;
        // }
        assert_ne!(index, u32::MAX, "index must be found");
        let mut s = Self::init_at_with_locked_outpoint(index, &transaction.locked_outpoint, wallet);
        s.registration_credit_funding_transaction = Some(transaction);
        Some(s)
    }

    pub fn init_at_with_credit_funding_transaction_and_username_dictionary(index: u32, transaction: &CreditFundingTransaction, username_dictionary: Option<HashMap<String, HashMap<String, UsernameInfoKind>>>, wallet: &Wallet) -> Option<Self> {
        //if (![transaction isCreditFundingTransaction]) return nil;
        assert_ne!(index, u32::MAX, "index must be found");
        if let Some(mut s) = Self::init_at_with_credit_funding_transaction(index, transaction, wallet) {
            if let Some(dict) = username_dictionary {
                let username_salts = HashMap::new();
                dict.iter().for_each(|(&username, &sub_dict)| {
                    if let Some(UsernameInfoKind::UsernameSalt(&salt)) = sub_dict.get(&BLOCKCHAIN_USERNAME_SALT) {
                        s.username_salts.insert(username, salt);
                    }
                });
                s.username_statuses = dict;
                s.username_salts = username_salts;
            }
            Some(s)
        }
        None
    }
    pub fn init_at_with_credit_funding_transaction_and_username_dictionary_and_credits(
        index: u32,
        transaction: &CreditFundingTransaction,
        username_dictionary: Option<HashMap<String, HashMap<String, UsernameInfoKind>>>,
        credits: u64,
        registration_status: RegistrationStatus,
        wallet: &Wallet) -> Option<Self> {
        if let Some(mut s) = Self::init_at_with_credit_funding_transaction_and_username_dictionary(index, transaction, username_dictionary, wallet) {
            s.credit_balance = credits;
            s.registration_status = registration_status;
            return Some(s);
        }
        None
    }

    pub fn init_with_identity_dictionary(identity_dictionary: HashMap<String, dyn SerializableValue>, version: u32, wallet: &Wallet) -> Option<Self> {
        let unique_id =
        if let Some(DocumentValue::UInt256(&unique_id)) = identity_dictionary.get("id") {
            unique_id
        } else {
            UInt256::MIN
        };
        let mut s = Self {
            wallet: Some(wallet),
            is_local: true,
            is_outgoing_invitation: false,
            is_transient: false,
            keys_created: 0,
            current_main_key_index: 0,
            current_main_key_type: KeyType::ECDSA,
            index,
            unique_id,
            username_statuses: HashMap::new(),
            key_info_dictionaries: HashMap::new(),
            registration_status: RegistrationStatus::Registered,
            username_salts: HashMap::new(),
            chain: wallet.chain,
            ..Default::default()
        };
        s.apply_identity_dictionary(identity_dictionary, version, false);
        // [self applyIdentityDictionary:identityDictionary version:version save:NO inContext:nil];

        Some(s)
    }

    pub fn init_with_identity_entity(entity: &IdentityEntity, chain: &Chain) -> Self {
        let mut s = Self::init_with(entity.unique_id, false, chain);
        s.apply_identity_entity(entity);
        s
    }




    /// This is the bitwise steps that the identity has already performed in registration.
    pub fn steps_completed(&self) -> RegistrationStep {
        let mut steps_completed = RegistrationStep::None;
        if self.is_registered {
            steps_completed = RegistrationStep::RegistrationSteps;
            if !self.username_full_paths_with_status(&UsernameStatus::Confirmed).is_empty() {
                steps_completed |= RegistrationStep::Username;
            }
        } else if let Some(tx) = &self.registration_credit_funding_transaction {
            steps_completed |= RegistrationStep::FundingTransactionCreation;
            if let Some(account) = self.chain.first_account_that_can_contain_transaction(tx) {
                if tx.base.block_height != TX_UNCONFIRMED || account.transaction_is_verified(tx) {
                    steps_completed |= RegistrationStep::FundingTransactionAccepted;
                }
            }
            if self.is_registered_in_wallet() {
                steps_completed |= RegistrationStep::LocalInWalletPersistence;
            }
            if tx.instant_send_lock_awaiting_processing.is_some() {
                steps_completed |= RegistrationStep::ProofAvailable;
            }
        }
        steps_completed
    }


    fn continue_registering_profile_on_network(&self, steps: RegistrationStep, steps_completed: RegistrationStep, step_completion: fn(RegistrationStep)) -> Result<RegistrationStep, Error> {
        let steps_already_completed = steps_completed.clone();
        if steps & RegistrationStep::Profile == 0 {
            Ok(steps_already_completed)
        } else {
            Ok(steps_completed)
        }
        // todo:we need to still do profile
    }

    fn continue_registering_usernames_on_network(&mut self, steps: RegistrationStep, mut steps_completed: RegistrationStep, step_completion: fn(RegistrationStep)) -> Result<RegistrationStep, Error> {
        let steps_already_completed = steps_completed.clone();
        if steps & RegistrationStep::Username == 0 {
            Ok(steps_already_completed)
        } else {
            match self.register_usernames_with_completion() {
                Ok(true) => {
                    step_completion(RegistrationStep::Username);
                    steps_completed |= RegistrationStep::Username;
                    self.continue_registering_profile_on_network(steps.clone(), steps_completed, step_completion)
                },
                Ok(false) => Ok(steps_completed),
                Err(err) => Err(err)
            })
        }
    }


    fn continue_registering_on_network(&mut self, steps: RegistrationStep, funding_account: Account, topup_amount: u64, context: &ManagedContext, step_completion:fn(RegistrationStep)) -> Result<RegistrationStep, Error> {
        if self.registration_credit_funding_transaction.is_some() {
            self.register_on_network(steps, funding_account, topup_amount, step_completion)
        } else if self.registration_status != RegistrationStatus::Registered {
            self.continue_registering_identity_on_network(steps, RegistrationStep::L1Steps, step_completion)
        } else if !self.unregistered_username_full_paths().is_empty() {
            self.continue_registering_usernames_on_network(steps, RegistrationStep::L1Steps | RegistrationStep::Identity, step_completion)
        } else if self.matching_dashpay_user_in_context(/*context*/).remote_profile_document_revision < 1 {
            self.continue_registering_profile_on_network(steps, RegistrationStep::L1Steps | RegistrationStep::Identity, step_completion)
        }
    }


    pub fn apply_identity_entity(&self, entity: &IdentityEntity) {
        todo!("impl store");

        for (DSBlockchainIdentityUsernameEntity *usernameEntity in blockchainIdentityEntity.usernames) {
            NSData *salt = usernameEntity.salt;
            if (salt) {
                [self.usernameStatuses setObject:@{BLOCKCHAIN_USERNAME_PROPER: usernameEntity.stringValue, BLOCKCHAIN_USERNAME_DOMAIN: usernameEntity.domain ? usernameEntity.domain : @"", BLOCKCHAIN_USERNAME_STATUS: @(usernameEntity.status), BLOCKCHAIN_USERNAME_SALT: usernameEntity.salt} forKey:[self fullPathForUsername:usernameEntity.stringValue inDomain:usernameEntity.domain]];
                [self.usernameSalts setObject:usernameEntity.salt forKey:usernameEntity.stringValue];
            } else {
                [self.usernameStatuses setObject:@{BLOCKCHAIN_USERNAME_PROPER: usernameEntity.stringValue, BLOCKCHAIN_USERNAME_DOMAIN: usernameEntity.domain ? usernameEntity.domain : @"", BLOCKCHAIN_USERNAME_STATUS: @(usernameEntity.status)} forKey:[self fullPathForUsername:usernameEntity.stringValue inDomain:usernameEntity.domain]];
            }
        }
        _creditBalance = blockchainIdentityEntity.creditBalance;
        _registrationStatus = blockchainIdentityEntity.registrationStatus;

        _lastCheckedProfileTimestamp = blockchainIdentityEntity.lastCheckedProfileTimestamp;
        _lastCheckedUsernamesTimestamp = blockchainIdentityEntity.lastCheckedUsernamesTimestamp;
        _lastCheckedIncomingContactsTimestamp = blockchainIdentityEntity.lastCheckedIncomingContactsTimestamp;
        _lastCheckedOutgoingContactsTimestamp = blockchainIdentityEntity.lastCheckedOutgoingContactsTimestamp;

        self.dashpaySyncronizationBlockHash = blockchainIdentityEntity.dashpaySyncronizationBlockHash.UInt256;

    }


    pub fn set_associated_invitation(&mut self, associated_invitation: &Invitation) {
        self.associated_invitation = Some(associated_invitation);
        if associated_invitation.created_locally {
            // It was created locally, we are sending the invite
            self.is_outgoing_invitation = true;
            self.is_from_incoming_invitation = false;
            self.is_local = false;
        } else {
            // It was created on another device, we are receiving the invite
            self.is_outgoing_invitation = false;
            self.is_from_incoming_invitation = true;
            self.is_local = true;
        }
    }

    pub fn is_registered_in_wallet(&self) -> bool {
        assert!(self.is_local, "This should not be performed on a non local blockchain identity");
        if !self.is_local {
            return false;
        }
        if let Some(w) = &self.wallet {
            w.contains_blockchain_identity(self)
        } else {
            false
        }
    }

    pub fn register_in_wallet(&self) {
        assert!(self.is_local, "This should not be performed on a non local blockchain identity");
        if !self.is_local { return; }
        if let Some(w) = &self.wallet {
            w.register_blockchain_identity(self);
            self.save_initial();
        }
    }

    pub fn register_in_wallet_for_registration_funding_transaction(&mut self, transaction: &CreditFundingTransaction) {
        assert!(self.is_local, "This should not be performed on a non local blockchain identity");
        if !self.is_local { return; }
        self.registration_credit_funding_transaction = Some(transaction);
        self.locked_outpoint = Some(&transaction.locked_outpoint());
        self.register_in_wallet_for_blockchain_identity_unique_id(transaction.credit_burn_identity_identifier());
        // we need to also set the address of the funding transaction to being used so future identities past the initial gap limit are found
        transaction.mark_address_as_used_in_wallet(self.wallet);
    }

    pub fn register_in_wallet_for_blockchain_identity_unique_id(&mut self, unique_id: UInt256) {
        assert!(self.is_local, "This should not be performed on a non local blockchain identity");
        if !self.is_local { return; }
        self.unique_id = unique_id;
        self.register_in_wallet();
    }




    pub fn create_new_key_of_type_in_context(&mut self, r#type: &KeyType, save_key: bool/*, context: NSManagedObjectContext*/) -> Option<(&dyn IKey, u32)> {
        if !self.is_local {
            return None;
        }
        let key_index = self.keys_created;
        let indexes = vec![self.index | BIP32_HARD, key_index | BIP32_HARD];
        let hardened_index_path = IndexPath::<u32>::index_path_with_indexes(indexes);
        if let Some(path) = self.derivation_path_for_type(r#type) {
            if let Some(public_key) = path.public_key_at_index_path(&hardened_index_path) {
                assert!(path.has_extended_private_key, "The derivation path should have an extended private key");
                let private_key = path.private_key_at_index_path::<u32>(&hardened_index_path);
                assert!(public_key, "These should be equal");
                self.keys_created += 1;
                let mut key_dictionary = HashMap::<KeyDictionary, dyn SerializableValue>::new();
                key_dictionary.insert(KeyDictionary::Key, &public_key);
                key_dictionary.insert(KeyDictionary::KeyType, r#type);
                key_dictionary.insert(KeyDictionary::KeyStatus, KeyStatus::Registering);
                self.key_info_dictionaries.insert(key_index, key_dictionary);
                if save_key {
                    self.save_new_key(public_key, hardened_index_path, KeyStatus::Registering, path/*, context*/);
                }
                return Some((&public_key, key_index));
            }
        }
        None
    }

    pub fn create_new_key_of_type(&mut self, r#type: &KeyType, save_key: bool) -> Option<(&dyn IKey, u32)> {
        self.create_new_key_of_type_in_context(r#type, save_key/*, [NSManagedObjectContext viewContext]*/)
    }

    pub fn active_keys_for_key_type(&self, r#type: &KeyType) -> Vec<&dyn IKey> {
        self.key_info_dictionaries.iter().filter_map(|(index, key_dictionary)| {
            match key_dictionary.get(&KeyDictionary::KeyType) {
                KeyInfoDictionaryValue::KeyType(key_type) if key_type == r#type => match key_dictionary.get(&KeyDictionary::Key) {
                    Some(KeyInfoDictionaryValue::Key(key)) => Some(key),
                    _ => None
                },
                _ => None
            }
        }).collect()
    }

    pub fn verify_keys_for_wallet(&mut self, wallet: &Wallet) -> bool {
        let original_wallet = self.wallet;
        self.wallet = Some(wallet);
        for index in 0..self.key_infor_dictionaries.len() {
            let key_type = self.type_of_key_at_index(index);
            let key = self.key_at_index(index);
            if key.is_none() {
                self.wallet = original_wallet;
                return false;
            }
            todo!("Check if it's possible when key_type not actually corresponds to trait implementation");
            if key_type == KeyType::ECDSA /*&& ![key isKindOfClass:[DSECDSAKey class]]*/ {
                self.wallet = original_wallet;
                return false;

            }
            if key_type == KeyType::BLS || key_type == KeyType::BLSBasic /*&& ![key isKindOfClass:[DSBLSKey class]]*/ {
                self.wallet = original_wallet;
                return false;
            }
            let derived_key = self.public_key_at_index(index, &key_type);
            if derived_key.public_key_data != key.public_key_data {
                self.wallet = original_wallet;
                return false;
            }
        }
        true
    }

    pub fn status_of_key_at_index(&self, index: u32) -> KeyStatus {
        if let Some(dictionary) = self.key_info_dictionaries.get(&index) {
            dictionary.get(&KeyDictionary::KeyStatus).unwrap() as KeyStatus
        } else {
            KeyStatus::default()
        }
    }

    pub fn type_of_key_at_index(&self, index: u32) -> KeyType {
        if let Some(dictionary) = self.key_info_dictionaries.get(&index) {
            if let Some(KeyInfoDictionaryValue::KeyType(&key_type)) = dictionary.get(&KeyDictionary::KeyType) {
                return key_type;
            }
        }
        KeyType::default()

    }

    pub fn key_at_index(&self, index: u32) -> Option<&dyn IKey> {
        if let Some(dictionary) = self.key_info_dictionaries.get(&index) {
            if let Some(KeyInfoDictionaryValue::Key(key)) = key_dictionary.get(&KeyDictionary::Key) {
                return Some(key);
            }
        }
        None
    }

    pub fn derivation_path_for_type_and_wallet(r#type: &KeyType, wallet: &Wallet) -> Option<AuthenticationKeysDerivationPath> {
        match r#type {
            KeyType::ECDSA => Some(wallet.chain.derivation_path_factory.blockchain_identity_ecdsa_keys_derivation_path_for_wallet(wallet)),
            KeyType::BLS => Some(wallet.chain.derivation_path_factory.blockchain_identity_bls_keys_derivation_path_for_wallet(wallet)),
            _ => None
        }
    }

    pub fn derivation_path_for_type(&self, r#type: &KeyType) -> Option<AuthenticationKeysDerivationPath> {
        if !self.is_local {
            None
        } else if let Some(wallet) = &self.wallet {
            Self::derivation_path_for_type_and_wallet(r#type, wallet)
        } else {
            None
        }
    }

    pub fn has_private_key_at_index(&self, index: u32, r#type: &KeyType) -> Result<bool, Error> {
        if !self.is_local {
            Ok(false)
        } else if let Some(mut path) = self.derivation_path_for_type(r#type) {
            let indexes = vec![self.index | BIP32_HARD, index | BIP32_HARD];
            let index_path = IndexPath::index_path_with_indexes(indexes);
            let key = self.identifier_for_key_at_path(&index_path, &mut path);
            match Keychain::get_data(key) {
                Ok(_data) => Ok(true),
                Err(_err) => Err(Error::Default(&format!("No data in keychain for key {}", key)))
            }
        } else {
            Err(Error::Default(&format!("No derivation path of type {:?}", r#type)))
        }
    }

    pub fn private_key_at_index(&self, index: u32, r#type: &KeyType) -> Option<&dyn IKey> {
        if !self.is_local {
            return None;
        }
        let indexes = vec![self.index | BIP32_HARD, index | BIP32_HARD];
        let index_path = IndexPath::index_path_with_indexes(indexes);
        if let Some(mut derivation_path) = self.derivation_path_for_type(r#type) {
            if let Some(key_secret) = Keychain::get_data(self.identifier_for_key_at_path(&index_path, &mut derivation_path)) {
                return r#type.key_with_private_key_data(key_secret, r#type);
            }
        }
        None
    }

    pub fn derive_private_key_at_identity_key_index(&self, index: u32, r#type: &KeyType) -> Option<&dyn IKey> {
        if !self.is_local {
            None
        } else {
            self.derive_private_key_at_index_path(&IndexPath::index_path_with_indexes(vec![self.index, index]), r#type)
        }
    }

    pub fn derive_private_key_at_index_path(&self, index_path: &IndexPath<u32>, r#type: &KeyType) -> Option<&dyn IKey> {
        if !self.is_local {
            None
        } else if let Some(path) = self.derivation_path_for_type(r#type) {
            path.private_key_at_index_path(&index_path.harden_all_items())
        } else {
            None
        }
    }

    pub fn private_key_at_index_for_seed(&self, index: u32, r#type: &KeyType, seed: &Vec<u8>) -> Option<&dyn IKey> {
        if !self.is_local {
            None
        } else if let Some(path) = self.derivation_path_for_type(r#type) {
            let indexes = vec![self.index | BIP32_HARD, index | BIP32_HARD];
            let index_path = IndexPath::index_path_with_indexes(indexes);
            path.private_key_at_index_path_from_seed(&index_path, Some(seed))
        }
    }




    pub fn public_key_at_index(&self, index: u32, r#type: &KeyType) -> Option<&dyn IKey> {
        if !self.is_local {
            None
        } else if let Some(derivation_path) = self.derivation_path_for_type(r#type) {
            let indexes = vec![self.index | BIP32_HARD, index | BIP32_HARD];
            let hardened_index_path = IndexPath::index_path_with_indexes(indexes);
            derivation_path.public_key_at_index_path(&hardened_index_path)
        } else {
            None
        }
    }


    pub fn registration_transition_signed_by_private_key(&self, private_key: &dyn IKey, public_keys: HashMap<u32, dyn IKey>, credit_funding_transaction: &CreditFundingTransaction) -> IdentityRegistrationTransition {
        let mut transition = IdentityRegistrationTransition::new(1, public_keys, credit_funding_transaction, self.chain);
        transition.sign_with_key(private_key, u32::MAX, self);
        transition
    }

    pub fn registration_transition(&self) -> Result<IdentityRegistrationTransition, Error> {
        match self.internal_registration_funding_private_key {
            Some(internal_registration_funding_private_key) => {
                let index = self.first_index_of_key_of_type(KeyType::ECDSA, true, !self.wallet.unwrap().is_transient);
                let public_key = self.key_at_index(index);
                assert_eq!(index & !BIP32_HARD, 0, "The index should be 0 here");
                if let Some(tx) = &self.registration_credit_funding_transaction {
                    if tx.base.instant_send_lock_awaiting_processing.is_none() && tx.block_height() == BLOCK_UNKNOWN_HEIGHT {
                        Err(Error::DefaultWithCode(&CREDIT_FUNDING_TRANSACTION_NOT_MINED.to_string(), 500))
                    } else {
                        Ok(self.registration_transition_signed_by_private_key(self.internal_registration_funding_private_key.unwrap(), HashMap::from([(index, public_key)]), tx))
                    }
                } else {
                    Err(Error::Default(&format!("The registration credit funding transaction must be known")))
                }
            },
            None => Err(Error::DefaultWithCode(&format!("The blockchain identity funding private key should be first created with create_funding_private_key"), 500))
        }
    }




    /// Registering

    pub fn create_and_publish_registration_transition(&mut self) -> Result<Option<HashMap<dyn SerializableKey, dyn SerializableValue>>, Error> {
        self.registration_transition().and_then(|transition| match self.dapi_client().publish_transition(&transition, &self.dispatch_context) {
            Ok((successDictionary, added)) => {
                match self.monitor_for_identity_with_retry_count(5, 5, 4, RetryDelayType::Linear, MonitorOptions::None, self.chain.platform_context()) {
                    Ok((success, found)) => Ok(successDictionary),
                    Err(err) => Err(err)
                }
            },
            Err(err) => {
                match self.monitor_for_identity_with_retry_count(1, 1, 4, RetryDelayType::Linear, MonitorOptions::None, self.chain.platform_context()) {
                    Ok((success, found)) if found => Ok(None),
                    Ok(..) => Err(Error::Default(&"Identity not found".to_string())),
                    Err(err) => Err(err)
                }
            }
        })
    }


    /// Retrieval
    pub fn fetch_identity_network_state_information(&mut self) -> Result<(bool, bool), Error> {
        self.fetch_identity_network_state_information_in_context(self.chain.platform_context(), &self.dispatch_context)
    }

    fn fetch_identity_network_state_information_in_context(&mut self, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<(bool, bool), Error> {
        // a local identity might not have been published yet
        // todo: retryabsentcount should be 0 if it can be proved to be absent
        self.monitor_for_identity_with_retry_count(DEFAULT_FETCH_IDENTITY_RETRY_COUNT, DEFAULT_FETCH_IDENTITY_RETRY_COUNT, 3, RetryDelayType::SlowingDown50Percent, if self.is_local { MonitorOptions::AcceptNotFoundAsNotAnError } else { MonitorOptions::None }, context)
    }

    pub fn fetch_all_network_state_information(&mut self) -> Result<QueryStep, Vec<Error>> {
        self.fetch_all_network_state_information_in_context(self.chain.platform_context(), &self.dispatch_context)
    }

    pub fn fetch_all_network_state_information_in_context(&mut self, context: &ManagedContext, dispach_context: &DispatchContext) -> Result<QueryStep, Vec<Error>> {
        let mut query = QueryStep::None;
        let sync_type = &self.chain.options.sync_type;
        if sync_type & SyncType::BlockchainIdentities != 0 {
            query |= QueryStep::Identity;
        }
        if sync_type & SyncType::DPNS != 0 {
            query |= QueryStep::Username;
        }
        if sync_type & SyncType::Dashpay != 0 {
            query |= QueryStep::Profile;
            if self.is_local {
                query |= QueryStep::ContactRequests;
            }
        }
        self.fetch_network_state_information_in_dispatch_context(&query, context, dispach_context)
    }

    pub fn fetch_l3_network_state_information(&mut self, query_step: &QueryStep) -> Result<QueryStep, Vec<Error>> {
        self.fetch_l3_network_state_information_in_context(query_step, self.chain.platform_context(), &DispatchContext::main_context())
    }

    pub fn fetch_l3_network_state_information_in_context(&mut self, query_step: &QueryStep, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<QueryStep, Vec<Error>> {
        if query_step & QueryStep::Identity == 0 && self.active_key_count == 0 {
            // We need to fetch keys if we want to query other information
            // Ok(QueryStep::BadQuery)
            return Err(vec![Error::DefaultWithCode(&QUERY_WITH_NO_ACTIVE_KEYS.to_string(), 501)]);
        }
        let mut failure_step = QueryStep::None;
        let mut grouped_errors = Vec::<Error>::new();
        let mut tasks = Vec::<fn(&DispatchContext)>::new();

        if query_step & QueryStep::Username != 0 {
            tasks.push(|ctx|
                match self.fetch_usernames_in_context(context, ctx) {
                    Ok(success) => failure_step |= success & QueryStep::Username,
                    Err(err) => {
                        failure_step |= success & QueryStep::Username;
                        grouped_errors.push(err)
                    }
                }
            )
        }
        if query_step & QueryStep::Profile != 0 {
            tasks.push(|ctx| {
                match self.fetch_profile_in_context(context, ctx) {
                    Ok(success) => failure_step |= success & QueryStep::Profile,
                    Err(err) => {
                        failure_step |= success & QueryStep::Profile;
                        grouped_errors.push(err)
                    }
                }

            })
        }
        if query_step & QueryStep::OutgoingContactRequests != 0 {
            tasks.push(|ctx| {
                match self.fetch_outgoing_contact_requests_in_context(context, ctx) {
                    Ok(success) => failure_step |= success & QueryStep::OutgoingContactRequests,
                    Err(err) => {
                        failure_step |= success & QueryStep::OutgoingContactRequests;
                        grouped_errors.push(err)
                    }
                }
            })
        }


        if (queryStep & DSBlockchainIdentityQueryStep_OutgoingContactRequests) {
            dispatch_group_enter(dispatchGroup);
            [self fetchOutgoingContactRequestsInContext:context
            withCompletion:^(BOOL success, NSArray<NSError *> *errors) {
                failure_step |= success & DSBlockchainIdentityQueryStep_OutgoingContactRequests;
                if ([errors count]) {
                [groupedErrors addObjectsFromArray:errors];
                dispatch_group_leave(dispatchGroup);
                } else {
                if (queryStep & DSBlockchainIdentityQueryStep_IncomingContactRequests) {
                [self fetchIncomingContactRequestsInContext:context
                withCompletion:^(BOOL success, NSArray<NSError *> *errors) {
                failureStep |= success & DSBlockchainIdentityQueryStep_IncomingContactRequests;
                if ([errors count]) {
                [groupedErrors addObjectsFromArray:errors];
                }
                dispatch_group_leave(dispatchGroup);
                }
                onCompletionQueue:self.identityQueue];
                } else {
                dispatch_group_leave(dispatchGroup);
                }
                }
            }
            onCompletionQueue:self.identityQueue];
        } else if (queryStep & DSBlockchainIdentityQueryStep_IncomingContactRequests) {
            dispatch_group_enter(dispatchGroup);
            [self fetchIncomingContactRequestsInContext:context
            withCompletion:^(BOOL success, NSArray<NSError *> *errors) {
                failure_step |= success & DSBlockchainIdentityQueryStep_IncomingContactRequests;
                if ([errors count]) {
                [groupedErrors addObjectsFromArray:errors];
                }
                dispatch_group_leave(dispatchGroup);
            }
            onCompletionQueue:self.identityQueue];
        }

        __weak typeof(self) weakSelf = self;
        if (completion) {
            dispatch_group_notify(dispatchGroup, self.identityQueue, ^{
                #if DEBUG
                DSLogPrivate(@"Completed fetching of blockchain identity information for user %@ (query %lu - failures %lu)",
                             self.currentDashpayUsername ? self.currentDashpayUsername : self.uniqueIdString,
                             (unsigned long)queryStep,
                failure_step);
                #else
                DSLog(@"Completed fetching of blockchain identity information for user %@ (query %lu - failures %lu)",
                      @"<REDACTED>",
                      (unsigned long)queryStep,
                failure_step);
                #endif /* DEBUG */
                if (!(failure_step & DSBlockchainIdentityQueryStep_ContactRequests)) {
                    __strong typeof(weakSelf) strongSelf = weakSelf;
                    if (!strongSelf) {
                        return;
                    }
                    //todo This needs to be eventually set with the blockchain returned by platform.
                    strongSelf.dashpaySyncronizationBlockHash = strongSelf.chain.lastTerminalBlock.blockHash;
                }
                dispatch_async(completionQueue, ^{
                    completion(failure_step, [groupedErrors copy]);
                });
            });
        }
    }

    pub fn fetch_network_state_information(&mut self, query_steps: &QueryStep, context: &ManagedContext) -> Result<QueryStep, Vec<Error>> {
        self.fetch_network_state_information_in_dispatch_context(query_steps, context, &DispatchContext::main_context())
    }

    pub fn fetch_network_state_information_in_dispatch_context(&mut self, query_steps: &QueryStep, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<QueryStep, Vec<Error>> {
        match query_steps & QueryStep::Identity {
            0 => self.fetch_l3_network_state_information_in_context(query_steps, context, dispatch_context),
            _ => match self.fetch_identity_network_state_information() {
                Ok((success, _)) if !success => Ok(QueryStep::Identity),
                Ok((_, found)) if !found => Ok(QueryStep::NoIdentity),
                Ok(..) => self.fetch_l3_network_state_information_in_context(query_steps, context, dispatch_context),
                Err(err) => Err(vec![err])
            }
        }
    }

    pub fn fetch_if_needed_network_state_information(&mut self, query_steps: &QueryStep, context: &ManagedContext) -> Result<QueryStep, Vec<Error>> {
        let check = |steps: QueryStep, context: &ManagedContext|
            if steps == QueryStep::None {
                Ok(QueryStep::None)
            } else {
                self.fetch_network_state_information(steps & query_steps, context)
            };
        match self.active_key_count {
            0 if self.is_local => self.fetch_network_state_information(query_steps, context),
            0 => check(self.steps_when_no_active_keys_exist(), context),
            _ => check(self.steps_when_having_active_keys(), context)
        }
    }

    pub async fn fetch_needed_network_state_information(&self) -> std::io::Result<QueryStep> {
        self.fetchNeededNetworkStateInformationInContext(self.chain.platform_context())
    }

    pub async fn fetch_needed_network_state_information_in_context(&mut self, context: &ManagedContext) -> Result<QueryStep, Vec<Error>> {
        let check = |steps: QueryStep, context: &ManagedContext|
            if steps == QueryStep::None {
                Ok(QueryStep::None)
            } else {
                self.fetch_network_state_information(&steps, context)
            };
        match self.active_key_count {
            0 if self.is_local => self.fetch_all_network_state_information(),
            0 => check(self.steps_when_no_active_keys_exist(), context),
            _ => check(self.steps_when_having_active_keys(), context)
        }
    }

    fn steps_when_no_active_keys_exist(&self) -> QueryStep {
        let mut steps_needed = QueryStep::None;
        let sync_type = &self.chain.options.sync_type;
        if sync_type & SyncType::BlockchainIdentities != 0 {
            steps_needed |= QueryStep::Identity;
        }
        if self.dashpay_username_full_paths().is_empty() && self.last_checked_usernames_timestamp == 0 && sync_type & SyncType::DPNS != 0 {
            steps_needed |= QueryStep::Username;
        }
        if self.last_checked_profile_timestamp < SystemTime::seconds_since_1970() - HOUR_TIME_INTERVAL && sync_type & SyncType::Dashpay != 0 {
            steps_needed |= QueryStep::Profile;
        }
        steps_needed
    }

    fn steps_when_having_active_keys(&self) -> QueryStep {
        let mut steps_needed = QueryStep::None;
        let sync_type = &self.chain.options.sync_type;
        if self.dashpay_username_full_paths().is_empty() && self.last_checked_usernames_timestamp == 0 && sync_type & SyncType::DPNS != 0 {
            steps_needed |= QueryStep::Username;
        }
        if self.matching_user_in_context(context).created_at != 0 && self.last_checked_profile_timestamp < SystemTime::seconds_since_1970() - HOUR_TIME_INTERVAL && sync_type & SyncType::Dashpay != 0 {
            steps_needed |= QueryStep::Profile;
        }
        if self.is_local && self.last_checked_incoming_contacts_timestamp < SystemTime::seconds_since_1970() - HOUR_TIME_INTERVAL && sync_type & SyncType::Dashpay != 0 {
            steps_needed |= QueryStep::IncomingContactRequests;
        }
        if self.is_local && self.last_checked_outgoing_contacts_timestamp < SystemTime::seconds_since_1970() - HOUR_TIME_INTERVAL && sync_type & SyncType::Dashpay != 0 {
            steps_needed |= QueryStep::OutgoingContactRequests;
        }
        steps_needed
    }

    /// Platform Helpers

    pub fn dashpay_document_factory(&mut self) -> &document::Factory {
        self.dashpay_document_factory.unwrap_or_else({
            let factory = document::Factory::new(self, &self.chain.platform().dash_pay_contract, self.chain);
            self.dashpay_document_factory = Some(&factory);
            &factory
        })
    }

    pub fn dpns_document_factory(&mut self) -> &document::Factory {
        self.dpns_document_factory.unwrap_or_else({
            let factory = document::Factory::new(self, &self.chain.platform().dpns_contract, self.chain);
            self.dpns_document_factory = Some(&factory);
            &factory
        })
    }

    fn dapi_client(&self) -> &dapi::Client {
        self.chain.dapi_client()
    }

    pub fn dapi_network_service(&self) -> &platform::Service {
        &self.dapi_client().platform_service
    }


    /// Signing and Encryption

    pub fn sign_state_transition_for_key_index(&mut self, mut transition: &dyn ITransition, key_index: u32, r#type: &KeyType) -> Result<bool, Error> {
        if let Some(private_key) = self.private_key_at_index(key_index, r#type) {
            if let Some(public_key_data) = private_key.public_key_data() {
                let public_key_data_at_index = self.public_key_at_index(key_index, r#type).public_key_data();
                assert_eq!(public_key_data, public_key_data_at_index, "These should be equal");
                transition.sign_with_key(private_key, key_index, &self);
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn sign_state_transition(&mut self, transition: &dyn ITransition) -> Result<bool, Error> {
        if self.keys_created == u32::MIN {
            self.create_new_key_of_type(&KeyType::default(),!self.wallet.unwrap().is_transient)
        }
        self.sign_state_transition_for_key_index(transition, self.current_main_key_index, &self.current_main_key_type)
    }

    pub fn sign_message_digest(&mut self, digest: UInt256, key_index: u32, r#type: &KeyType, completion: fn(bool, &Vec<u8>)) {
        if let Some(private_key) = self.private_key_at_index(key_index, r#type) {
            let public_key_data_at_index = self.public_key_at_index(key_index, r#type).public_key_data();
            assert_eq!(private_key.unwrap().public_key_data(), public_key_data_at_index, "These should be equal");
            private_key.sign_message_digest(digest, completion);
        } else {
            assert!(false, "The private key should exist");
        }
    }

    pub fn verify_signature(&self, signature: &Vec<u8>, r#type: &KeyType, message_digest: &Vec<u8>) -> bool {
        self.active_keys_for_key_type(r#type).iter().find(|public_key| public_key.verify(&message_digest, signature)).is_some()
    }

    pub fn verify_signature_for_key_index(&self, signature: &Vec<u8>, index: u32, r#type: &KeyType, message_digest: &UInt256) -> bool {
        match self.public_key_at_index(index, r#type) {
            Ok(public_key) => public_key.verify(message_digest, signature),
            Err(err) => false
        }
    }

    pub fn encrypt_data(&self, data: &Vec<u8>, index: u32, recipient_public_key: &dyn IKey) -> Result<&Vec<u8>, Error> {
        match self.private_key_at_index(index, recipient_public_key.r#type()) {
            Ok(private_key) => private_key.encrypt(data, recipient_public_key),
            Err(err) => Err(Error::Default(&format!("{:?}", err)))
        }
    }
    pub fn decrypt_data(&self, data: &Vec<u8>, index: u32, sender_public_key: &dyn IKey) -> Result<&Vec<u8>, Error> {
        match self.private_key_at_index(index, sender_public_key.r#type()) {
            Ok(private_key) => private_key.decrypt(data, sender_public_key),
            Err(err) => Err(Error::Default(&format!("{:?}", err)))
        }
    }

    /// Contracts

    pub async fn fetch_and_update_contract(&mut self, contract: &Contract) {
        self.fetch_and_update_contract_in_context(contract, self.chain.platform_context())
    }

    pub async fn fetch_and_update_contract_in_context(&mut self, contract: &Contract, context: &ManagedContext) {
        todo!("impl multithreaded flow for updating contract");
        let dispatch_context = DispatchContext::new(DispatchContextType::Global);
        dispatch_context.queue(|| {
            let is_dpns = contract.name.eq("DPNS");
            let is_dashpay = contract.name.eq("DashPay");
            let is_dpns_empty = is_dpns && self.chain.params.dpns_contract_id.is_zero();
            let is_dashpay_empty = is_dashpay && self.chain.params.dashpay_contract_id.is_zero();
            let is_other_contract = !(is_dpns || is_dashpay);
            let dispatch_context = DispatchContext::new(DispatchContextType::Global);
            if ((is_dpns_empty || is_dashpay_empty || is_other_contract) && contract.registered_blockchain_identity_unique_id.is_zero()) || contract.state == ContractState::NotRegistered {
                contract.register_creator(self, context);
                let transition = contract.contract_registration_transition_for_identity(self);
                match self.sign_state_transition(&transition) {
                    Ok(true) => match match self.dapi_client().publish_transition(&transition, &dispatch_context) {
                        Ok(_success_dictionary) => ContractState::Registering,
                        Err(_err) => ContractState::Unknown
                    } {
                        state => {
                            contract.set_contract_state(state, context);
                            match self.monitor_for_contract(contract, 2, context) {
                                Ok(success) => println!("monitor_for_contract: success: {}", success),
                                Err(err) => println!("monitor_for_contract: error: {:?}", err)
                            }
                        }
                    },
                    _ => {}
                }
            } else if contract.state == ContractState::Registered || contract.state == ContractState::Registering {
                println!("Fetching contract for verification {}", &contract.base58_contract_id);
                match self.dapi_network_service().fetch_contract_for_id(contract.contract_id.as_bytes_vec(), &dispatch_context) {
                    Ok(contract_dict) =>
                        match contract_dict.get(&ContractDictionaryKey::Documents) {
                            Some(ContractDictionaryValue::Documents(documents_dictionary)) => {
                                if contract.state == ContractState::Registered {
                                    let set1 = documents_dictionary.keys().collect::<HashSet<_>>();
                                    let set2 = contract.documents.keys().collect::<HashSet<_>>();
                                    if !set1.eq(&set2) {
                                        contract.set_contract_state(ContractState::NotRegistered, context);
                                    }
                                    println!("Contract dictionary is {}", contract_dict);
                                }
                            },
                            None => contract.set_contract_state(ContractState::Registered)
                        },
                    Err(err) => {
                        println!("Error: {}", err);
                        contract.set_contract_state(ContractState::NotRegistered);
                    }
                }
            }
        })
    }

    pub async fn fetch_and_update_contract_with_base58_identifier(&self, identifier: &String) {
        let dispatch_context = DispatchContext::new(DispatchContextType::Global);
        dispatch_context.queue(||
            match base58::from(identifier.as_str()) {
                Ok(base58data) =>
                    match self.dapi_network_service().fetch_contract_for_id(&base58data, &dispatch_context) {
                        Ok(contract) => println!("contract {:?}", contract),
                        Err(err) => println!("contract fetch error {:?}", err)
                    },
                Err(err) => println!("base58 error {:?}", err)
            })
    }

    /// DPNS

    /// Usernames
    pub fn add_dashpay_username(&mut self, username: String, save: bool) {
        self.add_username_in_domain_with_status(username, self.dashpay_domain_name().to_string(), UsernameStatus::Initial, save, true);
    }

    pub fn add_username_in_domain(&mut self, username: String, domain: String, save: bool) {
        self.add_username_in_domain_with_status(username, domain, UsernameStatus::Initial, save, true);
    }

    pub fn add_username_in_domain_with_status(&mut self, username: String, domain: String, status: UsernameStatus, save: bool, register_on_network: bool) {
        let key = Self::full_path_for_username(&username, &domain);
        let value = HashMap::from([
            (BLOCKCHAIN_USERNAME_STATUS.to_string(), UsernameInfoKind::UsernameStatus(&UsernameStatus::Initial)),
            (BLOCKCHAIN_USERNAME_PROPER.to_string(), UsernameInfoKind::UsernameProper(&username)),
            (BLOCKCHAIN_USERNAME_DOMAIN.to_string(), UsernameInfoKind::UsernameDomain(&domain)),
        ]);
        self.username_statuses.insert(key, value);
        if save {
            self.dispatch_context.queue(|| {
                self.save_new_username(&username, &domain, &UsernameStatus::Initial, self.chain.platform_context());
                if register_on_network && self.is_registered && status != UsernameStatus::Confirmed {
                    match self.register_usernames_with_completion() {
                        Ok(success) => println!("{}", success),
                        Err(err) => println!("{:?}", err)
                    };
                }
            });
        }
    }

    pub fn status_of_username(&self, username: &String, domain: &String) -> UsernameStatus {
        let full_path = Self::full_path_for_username(username, domain);
        self.status_of_username_full_path(&full_path)
    }

    pub fn status_of_dashpay_username(&self, username: &String) -> UsernameStatus {
        let domain = self.dashpay_domain_name();
        let full_path = Self::full_path_for_username(username, &domain.to_string());
        self.status_of_username_full_path(&full_path)
    }

    pub fn status_of_username_full_path(&self, username_full_path: &String) -> UsernameStatus {
        if let Some(data) = self.username_statuses.get(username_full_path) {
            if let Some(UsernameInfoKind::UsernameStatus(&status)) = data.get(&BLOCKCHAIN_USERNAME_STATUS) {
                return status;
            }
        }
        UsernameStatus::NotPresent
    }

    pub fn username_of_username_full_path(&self, username_full_path: &String) -> &String {
        if let Some(data) = self.username_statuses.get(username_full_path) {
            if let Some(UsernameInfoKind::UsernameProper(proper)) = data.get(&BLOCKCHAIN_USERNAME_PROPER) {
                return proper;
            }
        }
        &format!("")
    }

    pub fn domain_of_username_full_path(&self, username_full_path: &String) -> &String {
        if let Some(data) = self.username_statuses.get(username_full_path) {
            if let Some(UsernameInfoKind::UsernameDomain(domain)) = data.get(&BLOCKCHAIN_USERNAME_DOMAIN) {
                return domain;
            }
        }
        &format!("")
    }

    pub fn full_path_for_username(username: &String, domain: &String) -> String {
        format!("{}.{}", username.to_lowercase(), domain.to_lowercase())
    }

    pub fn dashpay_username_full_paths(&self) -> Vec<String> {
        self.username_statuses.keys().collect()
    }

    pub fn dashpay_usernames(&self) -> Vec<String> {
        self.username_statuses.keys().map(|username_full_path| self.username_of_username_full_path(username_full_path)).collect()
    }

    pub fn unregistered_username_full_paths(&self) -> Vec<String> {
        self.username_full_paths_with_status(&UsernameStatus::Initial)
    }

    pub fn username_full_paths_with_status(&self, username_status: &UsernameStatus) -> Vec<String> {
        self.username_statuses
            .iter()
            .filter_map(|(username, username_info)|
                match username_info.get(&BLOCKCHAIN_USERNAME_STATUS) {
                    Some(UsernameInfoKind::UsernameStatus(status)) if status == username_status => Some(username),
                    _ => None
                })
            .collect()
    }

    pub fn preordered_username_full_paths(&self) -> Vec<String> {
        self.username_statuses
            .iter()
            .filter_map(|(username, username_info)|
                match username_info.get(&BLOCKCHAIN_USERNAME_STATUS) {
                    Some(UsernameInfoKind::UsernameStatus(&UsernameStatus::Preordered)) => Some(username),
                    _ => None
                }
            ).collect()
    }

    /// Username Helpers
    pub fn salt_for_username_full_path(&mut self, username_full_path: &String, save_salt: bool, context: &ManagedContext) -> &UInt256 {
        let status = self.status_of_username_full_path(&username_full_path);
        let current_salt = self.username_salts.get(username_full_path);
        if status == UsernameStatus::Initial || current_salt.is_none() {
            let salt = UInt256::random();
            self.username_salts.insert(username_full_path.clone(), salt);
            if save_salt {
                self.save_username_in_domain(
                    self.username_of_username_full_path(username_full_path),
                    &self.domain_of_username_full_path(username_full_path),
                    &self.status_of_username_full_path(username_full_path),
                    Some(&salt),
                    true,
                    context);
            }
            &salt
        } else {
            current_salt.unwrap()
        }
    }

    pub fn salted_domain_hashes_for_username_full_paths(&mut self, username_full_paths: &Vec<String>, context: &ManagedContext) -> HashMap<String, UInt256> {
        let mut hashes = HashMap::<String, UInt256>::new();
        username_full_paths.iter().for_each(|unregistered_username_full_path| {
            let mut salted_domain = Vec::<u8>::new();
            let salt = self.salt_for_username_full_path(unregistered_username_full_path, true, context);
            let mut username_domain_data: Vec<u8> = Vec::new();
            unregistered_username_full_path.enc(&mut username_domain_data);
            salt.enc(&mut salted_domain);
            username_domain_data.enc(&mut salted_domain);
            let hash = UInt256(sha256d::Hash::hash(salted_domain.as_bytes()).into_inner());
            hashes.insert(unregistered_username_full_path.clone(), hash);
            self.username_salts.insert(unregistered_username_full_path.clone(), hash);
        });
        hashes
    }

    pub fn dashpay_domain_name(&self) -> &str {
        "dash"
    }

    /// Documents

    pub fn preorder_documents_for_unregistered_username_full_paths(&mut self, unregistered_username_full_paths: &Vec<String>, entropy_data: UInt256, context: &ManagedContext) -> Result<Vec<Document>, Error> {
        self.salted_domain_hashes_for_username_full_paths(unregistered_username_full_paths, context)
            .values()
            .filter_map(|salted_domain_hash_data|
                self.dpns_document_factory.document_on_table(
                    "preorder",
                    HashMap::from([("saltedDomainHash", UsernameInfoKind::UsernameSalt(salted_domain_hash_data))]),
                    entropy_data).ok())
            .collect()
    }

    pub fn domain_documents_for_unregistered_username_full_paths(&mut self, unregistered_username_full_paths: &Vec<String>, entropy: UInt256, context: &ManagedContext) -> Result<Vec<Document>, Error> {
        let mut documents = Vec::new();
        for (&username_full_path, _) in self.salted_domain_hashes_for_username_full_paths(unregistered_username_full_paths, context) {
            let username = self.username_of_username_full_path(username_full_path);
            let domain = self.domain_of_username_full_path(username_full_path);
            let data_dictionary: HashMap<dyn SerializableKey, dyn SerializableValue> = HashMap::from([
                (DataDictionaryKey::Label, username.clone()),
                (DataDictionaryKey::NormalizedLabel, username.to_lowercase()),
                (DataDictionaryKey::NormalizedParentDomainName, domain.clone()),
                (DataDictionaryKey::PreorderSalt, self.username_salts.get(username_full_path).unwrap()),
                (DataDictionaryKey::Records, Records::DashUniqueIdentityId(&self.unique_id)),
                (DataDictionaryKey::SubdomainRules, SubdomainRules::AllowSubdomains(false))
            ]);
            match self.dpns_document_factory.document_on_table_using_entropy(TableName::Domain, Some(data_dictionary), &entropy) {
                Ok(document) => documents.push(document),
                Err(_) => {
                    return Err(Error::Default(&format!("Error retrieve document")));
                }
            }
        }
        Ok(documents)
    }

    /// Transitions
    pub fn preorder_transition_for_unregistered_username_full_paths(&mut self, unregistered_username_full_paths: &Vec<String>, context: &ManagedContext) -> Result<DocumentTransition, Error> {
        match self.preorder_documents_for_unregistered_username_full_paths(unregistered_username_full_paths, UInt256::random(), context) {
            Ok(documents) if !documents.is_empty() =>
                Ok(DocumentTransition::init_for_documents(documents, 1, self.unique_id, self.chain)),
            _ => Err(Error::Default(&format!("no documents")))
        }
    }
    pub fn domain_transition_for_unregistered_username_full_paths(&mut self, unregistered_username_full_paths: &Vec<String>, context: &ManagedContext) -> Result<DocumentTransition, Error> {
        match self.domain_documents_for_unregistered_username_full_paths(unregistered_username_full_paths, UInt256::random(), context) {
            Ok(documents) if !documents.is_empty() =>
                Ok(DocumentTransition::init_for_documents(documents, 1, self.unique_id, self.chain)),
            _ => Err(Error::Default(&format!("no documents")))
        }
    }

    fn register_usernames_with_completion(&mut self) -> Result<bool, Error> {
        self.register_usernames_at_stage(
            UsernameStatus::Initial,
            self.chain.platform_context(),
            &DispatchContext::main_context())
    }

    fn register_usernames_at_stage(&mut self, status: UsernameStatus, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        println!("registerUsernamesAtStage {:?}", status);
        let username_full_paths = self.username_full_paths_with_status(&status);
        match status {
            UsernameStatus::Initial if username_full_paths.is_empty() =>
                self.register_usernames_at_stage(UsernameStatus::PreorderRegistrationPending, context, dispatch_context),
            UsernameStatus::Initial =>
                match self.register_preordered_salted_domain_hashes_for_username_full_paths(&username_full_paths, context, dispatch_context) {
                    Ok(true) => self.register_usernames_at_stage(UsernameStatus::PreorderRegistrationPending, context, dispatch_context),
                    Ok(false) => dispatch_context.post(Err(Error::Default(&format!("register_preordered_salted_domain_hashes_for_username_full_paths error")))),
                    Err(err) => dispatch_context.post(Err(err))
                },
            UsernameStatus::PreorderRegistrationPending => {
                let salted_domain_hashes = self.salted_domain_hashes_for_username_full_paths(&username_full_paths, context);
                if !salted_domain_hashes.is_empty() {
                    match self.monitor_for_dpns_preorder_salted_domain_hashes(&salted_domain_hashes, 4, context, dispatch_context) {
                        Ok(true) => self.register_usernames_at_stage(UsernameStatus::Preordered, context, dispatch_context),
                        Ok(false) => {
                            //todo: This needs to be done per username and not for all usernames
                            self.set_and_save_username_full_paths(&username_full_paths, &UsernameStatus::Initial, context);
                            self.register_usernames_at_stage(UsernameStatus::Initial, context, dispatch_context)
                        },
                        Err(err) => dispatch_context.post(Err(err))
                    }
                } else {
                    self.register_usernames_at_stage(UsernameStatus::Preordered, context, dispatch_context)
                }
            },
            UsernameStatus::Preordered if username_full_paths.is_empty() =>
                self.register_usernames_at_stage(UsernameStatus::RegistrationPending, context, dispatch_context),
            UsernameStatus::Preordered =>
                match self.register_username_domains_for_username_full_paths(&username_full_paths, context, dispatch_context) {
                    Ok(true) => self.register_usernames_at_stage(UsernameStatus::RegistrationPending, context, dispatch_context),
                    Ok(false) => dispatch_context.post(Err(Error::Default(&format!("register_username_domains_for_username_full_paths error")))),
                    Err(err) => dispatch_context.post(Err(err))
                },
            UsernameStatus::RegistrationPending if username_full_paths.is_empty() => dispatch_context.post(Ok(true)),
            UsernameStatus::RegistrationPending =>
                match self.monitor_for_dpns_username_full_paths(username_full_paths, 5, context, dispatch_context) {
                    Ok(false) => {
                        //todo: This needs to be done per username and not for all usernames
                        self.set_and_save_username_full_paths(&username_full_paths, &UsernameStatus::Preordered, context);
                        self.register_usernames_at_stage(UsernameStatus::Preordered, context, dispatch_context)
                    },
                    Ok(..) => dispatch_context.post(Ok(true)),
                    Err(err) => dispatch_context.post(Err(err))
                },
            _ => dispatch_context.post(Ok(false))
        }
    }

    /// Preorder stage
    fn register_preordered_salted_domain_hashes_for_username_full_paths(&mut self, username_full_paths: &Vec<String>, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        match self.preorder_transition_for_unregistered_username_full_paths(username_full_paths, context) {
            Ok(transition) =>
                match self.sign_state_transition(&transition) {
                    Ok(true) => {
                        // let's start by putting the usernames in an undetermined state
                        self.set_and_save_username_full_paths(username_full_paths, &UsernameStatus::PreorderRegistrationPending, context);
                        match self.dapi_client().publish_transition(&transition, &self.dispatch_context).await {
                            Ok((..)) => {
                                self.set_and_save_username_full_paths(username_full_paths, &UsernameStatus::Preordered, context);
                                dispatch_context.post(Ok(true))
                            },
                            Err(..) => dispatch_context.post(Ok(false))
                        }
                    },
                    _ => dispatch_context.post(Err(Error::DefaultWithCode(&format!("Unable to sign transition"), 501)))
                },
            Err(..) => dispatch_context.post(Ok(false))
        }
    }

    pub fn register_username_domains_for_username_full_paths(&mut self, username_full_paths: &Vec<String>, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        match self.domain_transition_for_unregistered_username_full_paths(username_full_paths, context) {
            Ok(transition) =>
                match self.sign_state_transition(&transition) {
                    Ok(success) if success => {
                        self.set_and_save_username_full_paths(username_full_paths, &UsernameStatus::RegistrationPending, context);
                        match self.dapi_client().publish_transition(&transition, &self.dispatch_context).await {
                            Ok((..)) => {
                                self.set_and_save_username_full_paths(username_full_paths, &UsernameStatus::Confirmed, context);
                                dispatch_context.post(Ok(true))
                            },
                            Err(..) => dispatch_context.post(Ok(false))
                        }
                    },
                    _ => dispatch_context.post(Ok(false))
                },
            Err(..) => dispatch_context.post(Ok(false))
        }
    }


    /// Retrieval
    pub fn fetch_usernames(&mut self) -> Result<bool, Error> {
        self.fetch_usernames_in_context(self.chain.platform_context(), &DispatchContext::main_context())
    }

    pub fn fetch_usernames_in_context(&mut self, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        self.fetch_usernames_in_context_with_retry_count(context, dispatch_context, DEFAULT_FETCH_USERNAMES_RETRY_COUNT)
    }

    pub fn fetch_usernames_in_context_with_retry_count(&mut self, context: &ManagedContext, dispatch_context: &DispatchContext, retry_count: u32) -> Result<bool, Error> {
        match self.internal_fetch_usernames_in_context(context, dispatch_context) {
            Ok(success) if !success && retry_count > 0 => self.fetch_usernames_in_context_with_retry_count(context, dispatch_context, retry_count - 1),
            Ok(..) => Err(Error::Default(&FETCH_USERNAMES_FAILED.to_string())),
            Err(err) => Err(err)
        }
    }

    fn internal_fetch_usernames_in_context(&mut self, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        let contract = &self.chain.platform().dpns_contract;
        if contract.state != ContractState::Registered {
            return Err(Error::DefaultWithCode(&DPNS_CONTRACT_NOT_REGISTERED.to_string(), 500));
        }
        match self.dapi_network_service()
            .get_dpns_documents_for_identity_with_user_id(&self.unique_id, dispatch_context) {
            Ok(documents) => {
                // todo verify return is true
                documents.iter().for_each(|name_dictionary| {
                    match (name_dictionary.get(&DataDictionaryKey::Label),
                           name_dictionary.get(&DataDictionaryKey::NormalizedLabel),
                           name_dictionary.get(&DataDictionaryKey::NormalizedParentDomainName)) {
                        (Some(username), Some(lowercase_username), Some(domain)) => {
                            let full_path = Self::full_path_for_username(lowercase_username, domain);
                            let mut is_new = false;
                            let mut username_status_dictionary = HashMap::<String, UsernameInfoKind>::new();
                            match self.username_statuses.get(&full_path) {
                                Some(dict) => {
                                    username_status_dictionary.extend(dict);
                                },
                                None => {
                                    is_new = true;
                                    username_status_dictionary.insert(BLOCKCHAIN_USERNAME_DOMAIN.to_string(), UsernameInfoKind::UsernameDomain(domain));
                                    username_status_dictionary.insert(BLOCKCHAIN_USERNAME_PROPER.to_string(), UsernameInfoKind::UsernameProper(username));
                                }
                            }
                            username_status_dictionary.insert(BLOCKCHAIN_USERNAME_STATUS.to_string(), UsernameInfoKind::UsernameStatus(&UsernameStatus::Confirmed));
                            self.username_statuses.insert(full_path, username_status_dictionary);
                            if is_new {
                                self.save_new_username(username, domain, &UsernameStatus::Confirmed, context)
                            } else {
                                self.save_username_in_domain(username, domain, &UsernameStatus::Confirmed, None, true, context)
                            }
                        },
                        _ => {}
                    }
                });
                Ok(true)
            },
            Err(err) => match err {
                // UNIMPLEMENTED, this would mean that we are connecting to an old node
                Error::DefaultWithCode(_, code) if code == 12 => {
                    self.dapi_client().remove_dapi_node_by_address(&self.dapi_network_service().ip_address);
                    self.fetch_usernames_in_context(context, dispatch_context)
                },
                _ => Err(err)
            }
        }
    }

    /// Monitoring
    pub fn update_credit_balance(&mut self) {
        // this is so we don't get DAPINetworkService immediately
        // dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)
        DispatchContext::new(DispatchContextType::Global).queue(||
            match self.dapi_network_service().get_identity_by_id(&self.unique_id, &self.dispatch_context) {
                Ok(profile_dictionary) => {
                    if let Some(ProfileDictionaryValue::Balance(credit_balance)) = profile_dictionary.get(&ProfileDictionaryKey::Balance) {
                        // todo perform in identity_context
                        self.dispatch_context.queue(|| self.credit_balance = credit_balance);
                    }
                },
                // UNIMPLEMENTED, this would mean that we are connecting to an old node
                Err(Error::DefaultWithCode(message, code)) if code == 12 => self.dapi_client().remove_dapi_node_by_address(self.dapi_network_service().ip_address),
                _ => {}
            });
    }

    pub fn monitor_for_identity_with_retry_count(&mut self, retry_count: u32, retry_absent_count: u32, delay: u64, retry_delay_type: RetryDelayType, options: MonitorOptions, context: &ManagedContext) -> Result<(bool, bool), Error> {
        match self.dapi_network_service().get_identity_by_id(&self.unique_id, &self.dispatch_context) {
            Ok(versionedIdentityDictionary) => {
                // if (!versionedIdentityDictionary) {
                //     if (completion) {
                //         if (options & DSBlockchainIdentityMonitorOptions_AcceptNotFoundAsNotAnError) {
                //             completion(YES, NO, nil);
                //             return;
                //         } else {
                //             completion(NO, NO, [NSError errorWithCode:500 localizedDescriptionKey:@"Platform returned no identity when one was expected"]);
                //             return;
                //         }
                //     }
                // }
                //
                // if (![versionedIdentityDictionary respondsToSelector:@selector(objectForKey:)]) {
                // completion(YES, NO, nil);
                // return;
                // }
                match (versionedIdentityDictionary.get(&StoredMessage::Version),
                       versionedIdentityDictionary.get(&StoredMessage::Item)) {
                    (Some(version), Some(identityDictionary)) => {
                        if !identityDictionary.is_empty() {
                            self.apply_identity_dictionary(identityDictionary, version, !self.is_transient, context);
                            self.registration_status = RegistrationStatus::Registered;
                            self.save_in_context(context);
                        }
                        Ok((true, true))
                    },
                    _ => if options & MonitorOptions::AcceptNotFoundAsNotAnError != 0 {
                        Ok((true, false))
                    } else {
                        Err(Error::DefaultWithCode(&NO_IDENTITY_RETURNED.to_string(), 500))
                    }
                }
            },
            Err(err) => {
                if err.code() == 12 {
                    // UNIMPLEMENTED, this would mean that we are connecting to an old node
                    self.dapi_client().remove_dapi_node_by_address(self.dapi_network_service().ip_address);
                }
                let mut next_retry_absent_count = retry_absent_count;
                if err.message() == "Identity not found" {
                    if retry_absent_count == 0 {
                        return if options & MonitorOptions::AcceptNotFoundAsNotAnError != 0 {
                            Ok((true, false))
                        } else {
                            Err(err)
                        };
                    }
                    next_retry_absent_count -= 1;
                }
                if retry_count > 0 {
                    // dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC))
                    DispatchContext::main_context().after(DispatchTime::delay(delay)).and_then(|ctx| {
                        let mut next_delay = delay;
                        match retry_delay_type {
                            RetryDelayType::SlowingDown20Percent => next_delay = delay * 1.2,
                            RetryDelayType::SlowingDown50Percent => next_delay = delay * 1.5,
                            _ => {}
                        }
                        self.monitor_for_identity_with_retry_count(retry_count - 1, next_retry_absent_count, next_delay, retry_delay_type, options, context)
                    })
                } else {
                    Err(error)
                }

            }
        }
    }

    pub fn monitor_for_dpns_username_full_paths(&self, username_full_paths: Vec<String>, retry_count: u32, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        let domains = username_full_paths
            .iter()
            .fold(HashMap::<String, Vec<String>>::new(), |mut domains, username_full_path| {
                let mut components = username_full_path.split(".").collect::<Vec<_>>();
                let name = components.first().unwrap();
                let domain = if components.len() > 1 {
                    components.drain(1..components.len() - 1).join(".")
                } else {
                    String::new()
                };
                domains.entry(domain).or_insert(vec![]).push(name.to_string());
                domains
            });
        todo!("impl group task")
        /*
        let mut finished = false;
        let mut count_all_found = 0usize;
        let mut count_returned = 0usize;

        for (domain, usernames) in domains {
            match self.monitor_for_dpns_usernames(usernames, &domain, retry_count, context, dispatch_context) {
                Ok(all_found) => {
                    if finished {
                        return Ok(true);
                    }
                    if all_found {
                        count_all_found += 1;
                    }
                    count_returned += 1;
                    if count_returned == domains.len() {
                        finished = true;
                        return Ok(count_all_found == domains.len());
                    }
                    return Ok(false);
                },
                Err(err) if finished => Ok(true),
                Err(err) => {
                    finished = true;
                    return Err(err);
                }
            }
        }*/
    }




    pub fn monitor_for_dpns_usernames(&mut self, usernames: &Vec<String>, domain: &String, retry_count: u32, context: &NSManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        match self.dapi_network_service().get_dpns_documents_for_usernames_in_domain(usernames, domain, &self.dispatch_context) {
            Ok(domainDocumentArray) => {
                let mut usernames_left = usernames.clone();
                usernames.iter().for_each(|&username| {
                    domainDocumentArray.iter().for_each(|domain_document| {
                        match (domain_document.get(&DataDictionaryKey::Label),
                               domain_document.get(&DataDictionaryKey::NormalizedLabel),
                               domain_document.get(&DataDictionaryKey::NormalizedParentDomainName)) {
                            (Some(label), Some(normalized_label), Some(normalized_parent_domain_name)) => {
                                if normalized_label == username.to_lowercase() {
                                    let username_status_dictionary = self.username_statuses.entry(username).or_insert(HashMap::from([
                                        (BLOCKCHAIN_USERNAME_DOMAIN.to_string(), UsernameInfoKind::UsernameDomain(normalized_parent_domain_name)),
                                        (BLOCKCHAIN_USERNAME_PROPER.to_string(), UsernameInfoKind::UsernameProper(label)),
                                    ]));
                                    username_status_dictionary.insert(BLOCKCHAIN_USERNAME_STATUS.to_string(), UsernameInfoKind::UsernameStatus(&UsernameStatus::Confirmed));
                                    self.username_statuses.insert(Self::full_path_for_username(&username, self.current_dashpay_username()), username_status_dictionary.clone());
                                    self.save_username_in_domain(&username, normalized_parent_domain_name, &UsernameStatus::Confirmed, None, true, context);
                                    if let Some(pos) = usernames_left.iter().position(|name| name == username) {
                                        usernames_left.remove(pos);
                                    }
                                }
                            }
                            _ => {}
                        }
                    });
                });
                if !usernames_left.is_empty() {
                    if retry_count > 0 {
                        self.monitor_for_dpns_usernames(&usernames_left, domain, retry_count - 1, context, dispatch_context)
                    } else {
                        dispatch_context.post(Ok(false))
                    }
                } else {
                    dispatch_context.post(Ok(true))
                }
            },
            Err(err) if retry_count > 0 => self.dispatch_context.queue(|| self.monitor_for_dpns_usernames(usernames, domain, retry_count - 1, context, dispatch_context)),
            Err(err) => Err(Error::DefaulWithCode(&"Malformed platform response".to_string(), 501))
        }
    }

    pub fn monitor_for_dpns_preorder_salted_domain_hashes(&mut self, salted_domain_hashes: &HashMap<String, UInt256>, retry_count: u32, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        match self.dapi_network_service().get_dpns_documents_for_preorder_salted_domain_hashes(salted_domain_hashes.values().collect(), dispatch_context) {
            Ok(preorderDocumentArray) => {
                let mut usernames_left = salted_domain_hashes.keys().collect::<Vec<_>>();
                salted_domain_hashes.iter().for_each(|(&username_full_path, saltedDomainHashData)| {
                    preorderDocumentArray.iter().for_each(|preorder_document| {
                        match preorder_document.get(&PreorderDictionaryKey::SaltedDomainHash) {
                            Some(salted_domain_hash) => if salted_domain_hash == saltedDomainHashData {
                                let username_status_dictionary = self.username_statuses.entry(username_full_path).or_insert(HashMap::new());
                                let new_status = UsernameStatus::Preordered;
                                username_status_dictionary.insert(BLOCKCHAIN_USERNAME_STATUS.to_string(), UsernameInfoKind::UsernameStatus(&new_status));
                                self.username_statuses.insert(username_full_path.clone(), username_status_dictionary.clone());
                                self.save_username_full_path(&username_full_path, &new_status, None, true, context);
                                if let Some(pos) = usernames_left.iter().position(|name| full_path == username_full_path) {
                                    usernames_left.remove(pos);
                                }
                            },
                            None => {}
                        }
                    });
                });
                if !usernames_left.is_empty() {
                    if retry_count > 0 {
                        self.monitor_for_dpns_preorder_salted_domain_hashes(
                            salted_domain_hashes
                                .iter()
                                .filter(|(name,_)| usernames_left.contains(name))
                                .collect(),
                            retry_count - 1, context, dispatch_context)
                    } else {
                        dispatch_context.post(Ok(false))
                    }
                } else {
                    dispatch_context.post(Ok(true))
                }
            },
            Err(err) if retry_count > 0 =>
                self.dispatch_context.queue(|| self.monitor_for_dpns_preorder_salted_domain_hashes(salted_domain_hashes, retry_count - 1, context, dispatch_context)),
            Err(err) =>
                dispatch_context.post(Err(Error::DefaulWithCode(&"Malformed platform response".to_string(), 501)))
        }
    }

    pub fn monitor_for_contract(&self, contract: &Contract, retry_count: u32, context: &ManagedContext) -> Result<bool, Error> {
        match self.dapi_network_service().fetch_contract_for_id(contract.contract_id.as_bytes_vec(), &self.dispatch_context) {
            Ok(contract_dictionary) => match contract_dictionary.get(&ContractDictionaryKey::Id) {
                Some(ContractDictionaryValue::Id(id)) if id == contract.contract_id_bytes() => {
                    contract.set_contract_state(ContractState::Registered, context);
                    Ok(true)
                },
                _ if retry_count > 0 => self.monitor_for_contract(contract, retry_count - 1, context),
                _ => Err(Error::DefaultWithCode(&format!("Malformed platform response"), 501))
            },
            Err(err) => {
                match err {
                    // UNIMPLEMENTED, this would mean that we are connecting to an old node
                    Error::DefaultWithCode(_, code) if code == 12 => {
                        self.dapi_client().remove_dapi_node_by_address(self.dapi_network_service().ip_address);
                    },
                    _ => {}
                }
                if retry_count > 0 {
                    DispatchContext::main_context().queue(|| self.monitor_for_contract(contract, retry_count - 1, context))
                } else {
                    Err(err)
                }
            }
        }
    }


    /// Dashpay

    /// Helpers
    pub fn is_dashpay_ready(&self) -> bool {
        self.active_key_count != 0 && self.is_registered
    }

    pub fn matching_dashpay_user_profile_document_in_context(&mut self, context: &ManagedContext) -> Option<Document> {
        // The revision must be at least at 1, otherwise nothing was ever done
        match self.matching_dashpay_user_in_context(context) {
            Some(matching_dashpay_user) if matching_dashpay_user.local_profile_document_revision != 0 => {
                let mut data_dictionary = HashMap::<ProfileDataDictionaryKey, dyn SerializableValue>::new();
                data_dictionary.insert(ProfileDataDictionaryKey::UpdatedAt, Records::Timestamp(&matching_dashpay_user.updated_at));
                if matching_dashpay_user.created_at == matching_dashpay_user.updated_at {
                    data_dictionary.insert(ProfileDataDictionaryKey::CreatedAt, matching_dashpay_user.created_at);
                } else {
                    data_dictionary.insert(ProfileDataDictionaryKey::Revision, matching_dashpay_user.local_profile_document_revision);
                }
                if let Some(public_message) = matching_dashpay_user.public_message {
                    data_dictionary.insert(ProfileDataDictionaryKey::PublicMessage, public_message);
                }
                if let Some(avatar_path) = matching_dashpay_user.avatar_path {
                    data_dictionary.insert(ProfileDataDictionaryKey::AvatarUrl, avatar_path);
                }
                if let Some(avatar_fingerprint) = matching_dashpay_user.avatar_fingerprint {
                    data_dictionary.insert(ProfileDataDictionaryKey::AvatarFingerprint, avatar_fingerprint);
                }
                if let Some(avatar_hash) = matching_dashpay_user.avatar_hash {
                    data_dictionary.insert(ProfileDataDictionaryKey::AvatarHash, avatar_hash);
                }
                if let Some(display_name) = matching_dashpay_user.display_name {
                    data_dictionary.insert(ProfileDataDictionaryKey::DisplayName, display_name);
                }
                match (matching_dashpay_user.document_id, matching_dashpay_user.original_entropy_data) {
                    (None, Some(entropy)) =>
                        self.dashpay_document_factory().document_on_table_using_entropy(TableName::Profile, Some(data_dictionary), &entropy).ok(),
                    (Some(document_id), _) =>
                        self.dashpay_document_factory().document_on_table_using_document_identifier(TableName::Profile, Some(data_dictionary), &document_id).ok(),
                    _ => None
                }
            },
            _ => None
        }
    }


    pub fn friendship_status_for_relationship_with_identity(&self, identity: &Identity) -> FriendshipStatus {
        match self.matching_dashpay_user_in_view_context() {
            Some(user) => {
                let is_incoming_bit: i16 = if user.num_of_incoming_requests_for_other_identity_unique_id(&identity.unique_id, self.chain.view_context()).unwrap_or(0) > 0 { 1 } else { 0 };
                let is_outgoing_bit: i16 = if user.num_of_outgoing_requests_for_other_identity_unique_id(&identity.unique_id, self.chain.view_context()).unwrap_or(0) > 0 { 1 } else { 0 };
                FriendshipStatus::from( (is_incoming_bit << 1) | is_outgoing_bit)
            },
            None => FriendshipStatus::Unknown
        }
    }

    /// Sending a Friend Request
    pub fn set_dashpay_synchronization_block_hash(&mut self, block_hash: &UInt256) {
        self.dashpay_syncronization_block_hash = Some(block_hash);
        if block_hash.is_zero() {
            self.dashpay_syncronization_block_height = 0;
        } else {
            let h = self.chain.height_for_block_hash(block_hash);
            self.dashpay_syncronization_block_height = if h == u32::MAX { 0 } else { h };
        }
    }

    /// Sending a Friend Request
    pub fn send_new_friend_request_to_identity(&mut self, identity: &mut Identity) -> Result<bool, Vec<Error>> {
        self.send_new_friend_request_to_identity_in_context(identity, self.chain.platform_context(), &DispatchContext::main_context())
    }

    pub fn send_new_friend_request_to_identity_in_context(&mut self, identity: &mut Identity, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        if identity.is_transient {
            identity.is_transient = false;
            self.chain.identities_manager().register_foreign_identity(identity);
            if let Some(transient_user) = &identity.transient_dashpay_user {
                match identity.apply_profile_changes(transient_user, true, context, &self.dispatch_context) {
                    Ok(true) =>
                        match identity.matching_dashpay_user_in_context(context) {
                            Some(dashpay_user) if transient_user.revision == dashpay_user.remote_profile_document_revision => {
                                identity.transient_dashpay_user = None;
                            },
                            _ => {}
                        },
                    _ => {}
                }
            }
        }
        match identity.fetch_needed_network_state_information_in_context(context) {
            Ok(failure_step) => {
                if failure_step != 0 && failure_step != QueryStep::Profile { //if profile fails we can still continue on
                    // completion(NO, errors);
                    // todo: check correct return here
                    return Ok(false);
                }
                if !identity.is_dashpay_ready() {
                    return dispatch_context.post(Err(vec![Error::DefaultWithCode(&format!("User has actions to complete before being able to use Dashpay"), 501)]));
                }
                let destination_key_index = identity.first_index_of_key_of_type(&self.current_main_key_type, false, false);
                let source_key_index = self.first_index_of_key_of_type(&self.current_main_key_type, false, false);
                if source_key_index == u32::MAX { //not found
                    // to do register a new key
                    assert!(false, "we shouldn't be getting here");
                    return dispatch_context.post(Err(vec![Error::DefaultWithCode(&format!("Internal key handling error"), 501)]));
                }
                let account = self.wallet.unwrap().account_with_number(0);
                let mut potential_friendship = PotentialOneWayFriendship::init_with_destination_identity(identity, destination_key_index, self, source_key_index, account);
                match potential_friendship.create_derivation_path_and_save_extended_public_key() {
                    Ok((success, incoming_funds_derivation_path)) =>
                        match potential_friendship.encrypt_extended_public_key() {
                            Ok(true) => self.send_new_friend_request_matching_potential_friendship_in_context(&potential_friendship, context, dispatch_context),
                            _ => dispatch_context.post(Err(vec![Error::DefaultWithCode(&format!("Internal key handling error"), 501)]))
                        },
                    _ => dispatch_context.post(Err(vec![Error::DefaultWithCode(&format!("Internal key handling error"), 501)]))
                }
            },
            Err(errors) => Err(errors)
        }
    }

    pub fn send_new_friend_request_to_potential_contact(&mut self, potential_contact: PotentialContact) -> Result<bool, Vec<Error>> {
        match self.dapi_network_service()
            .get_identity_by_name(&potential_contact.username, &self.dashpay_domain_name().to_string(), &self.dispatch_context) {
            Ok(identity_versioned_dict) => {
                match (identity_versioned_dict.get(&StoredMessage::Version),
                       identity_versioned_dict.get(&StoredMessage::Item)) {
                    (Some(version), Some(identity_dict)) if identity_dict.contains_key("id") => {
                        let identity_contact_unique_id: UInt256 = identity_dict.get("id").unwrap();
                        assert!(!identity_contact_unique_id.is_zero(), "blockchainIdentityContactUniqueId should not be null");
                        let mut potential_contact_identity = if let Some(potential_contact_identity_entity) = IdentityEntity::identity_with_unique_id(&identity_contact_unique_id, self.chain.platform_context()) {
                            self.chain.blockchain_identity_for_unique_id(identity_contact_unique_id)
                                .unwrap_or(&Identity::init_with_identity_entity(&potential_contact_identity_entity, self.chain))
                        } else {
                            self.chain.identitites_manager()
                                .foreign_identity_with_unique_id(identity_contact_unique_id, true, self.chain.platform_context())
                        };
                        potential_contact_identity.apply_identity_dictionary(identity_dict, version, true, self.chain.platform_context());
                        potential_contact_identity.save_in_context(self.chain.platform_context());
                        self.send_new_friend_request_to_identity(&potential_contact_identity)
                    },
                    _ => DispatchContext::main_context().post(Err(vec![Error::DefaultWithCode(&format!("Malformed platform response"), 501)]))
                }
            },
            Err(err) => {
                match err {
                    // UNIMPLEMENTED, this would mean that we are connecting to an old node
                    Error::DefaultWithCode(_, code) if code == 12 => {
                        self.dapi_client().remove_dapi_node_by_address(self.dapi_network_service().ip_address);
                    },
                    _ => {}
                }
                DispatchContext::main_context().post(Err(vec![err]))
            }
        }
    }

    pub fn send_new_friend_request_matching_potential_friendship(&mut self, potential_friendship: &PotentialOneWayFriendship) -> Result<bool, Vec<Error>> {
        self.send_new_friend_request_matching_potential_friendship_in_context(potential_friendship, self.chain.platform_context(), &DispatchContext::main_context())
    }

    pub fn send_new_friend_request_matching_potential_friendship_in_context(&mut self, potential_friendship: &PotentialOneWayFriendship, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        if !self.is_local {
            return Err(vec![Error::Default(&format!("This should not be performed on a non local blockchain identity"))]);
        }
        match potential_friendship.destination_identity.matching_dashpay_user_in_context(context) {
            None => Err(vec![Error::Default(&format!("There must be a destination contact if the destination blockchain identity is not known"))]),
            Some(destination_user) => {
                let contract = &self.chain.platform().dash_pay_contract;

                let entropy = UInt256::random();
                let document = potential_friendship.contact_request_document_with_entropy(&entropy);
                match self.dapi_client().send_document(document, self, contract) {
                    Ok(result) => {
                        self.add_friendship_in_context(potential_friendship, context);
                        self.fetch_outgoing_contact_requests_in_context(context)
                        // [self fetchOutgoingContactRequestsInContext:context
                        // withCompletion:^(BOOL success, NSArray<NSError *> *_Nonnull errors) {
                        //     if (completion) {
                        //         dispatch_async(dispatch_get_main_queue(), ^{
                        //             completion(success, errors);
                        //         });
                        //     }
                        // }

                    },
                    Err(err) =>
                        DispatchContext::main_context().post(Err(err))
                }
            }
        }
    }


    pub fn accept_friend_request_from_blockchain_identity(&mut self, other_identity: &Identity) -> Result<bool, Vec<Error>> {
        self.accept_friend_request_from_blockchain_identity_in_context(other_identity, self.chain.platform_context(), &DispatchContext::main_context())
    }

    pub fn accept_friend_request_from_blockchain_identity_in_context(&mut self, other_identity: &Identity, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        assert!(self.is_local, "This should not be performed on a non local blockchain identity");
        if !self.is_local {
            return Err(vec![Error::DefaultWithCode(&format!("Accepting a friend request should only happen from a local blockchain identity"), 501)]);
        }
        // [context performBlockAndWait:^{
        match self.matching_dashpay_user_in_context(context) {
            Some(user) =>
                match user.incoming_request_aggregate_for_identity_with_unique_id(&other_identity.unique_id, context) {
                    Ok(aggregate) => self.accept_friend_request(&aggregate),
                    Err(_) => Err(vec![Error::DefaultWithCode(&format!("You can only accept a friend request from blockchain identity who has sent you one, and none were found"), 501)])
                },
            None => Err(vec![Error::Default(&format!("No user in context"))])
        }
    }

    pub fn accept_friend_request(&mut self, request: &FriendRequestAggregate) -> Result<bool, Vec<Error>> {
        self.accept_friend_request_in_dispatch_context(request, &DispatchContext::main_context())
    }

    pub fn accept_friend_request_in_dispatch_context(&mut self, request: &FriendRequestAggregate, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        assert!(self.is_local, "This should not be performed on a non local blockchain identity");
        if !self.is_local {
            return Err(vec![Error::DefaultWithCode(&format!("Accepting a friend request should only happen from a local blockchain identity"), 501)]);
        }

        let account = self.wallet.unwrap().account_with_number(0);
        let other_dashpay_user = &request.user;
        let other_identity = self.chain.blockchain_identity_for_unique_id(request.identity.unique_id)
            .unwrap_or(&Identity::init_with_identity_entity(&request.identity, self.chain));

        let mut potential_friendship = PotentialOneWayFriendship::init_with_destination_identity(
            other_identity,
            request.request.source_key_index as u32,
            self,
            request.request.destination_key_index as u32,
            account);

        let incoming_funds_derivation_path = potential_friendship.create_derivation_path_and_save_extended_public_key();
        match potential_friendship.encrypt_extended_public_key() {
            Ok(true) => self.send_new_friend_request_matching_potential_friendship_in_context(&potential_friendship, &request.context, dispatch_context),
            _ => DispatchContext::main_context().post(Err(vec![Error::DefaultWithCode(&format!("Internal key handling error"), 501)]))
        }
    }

    /// Profile
    pub fn profile_document_transition_in_context(&mut self, context: &ManagedContext) -> Option<DocumentTransition> {
        self.matching_dashpay_user_profile_document_in_context(context)
            .and_then(|profile_document|
                Some(DocumentTransition::init_for_documents(
                    vec![profile_document],
                    1,
                    self.unique_id,
                    self.chain)))
    }

    fn update_dashpay_profile_with(&self, updater: fn(UserEntity) -> QueryResult<usize>) {
        match self.matching_dashpay_user_in_context(context) {
            Some(user) => match updater(user) {
                Ok(updated) => println!("update_dashpay_profile_with: count: {}", updated),
                Err(err) => println!("update_dashpay_profile_with: error: {:?}", err)
            },
            None => {}
        }
    }

    pub fn update_dashpay_profile_with_display_name(&self, display_name: String) {
        self.update_dashpay_profile_with_display_name_in_context(display_name, self.chain.platform_context())
    }

    pub fn update_dashpay_profile_with_display_name_in_context(&self, display_name: String, context: &ManagedContext) {
        self.update_dashpay_profile_with(|user|
            user.update_with_display_name(display_name, context));
    }


    pub fn update_dashpay_profile_with_public_message(&self, public_message: String) {
        self.update_dashpay_profile_with_public_message_in_context(public_message, self.chain.platform_context())
    }

    pub fn update_dashpay_profile_with_public_message_in_context(&self, public_message: String, context: &ManagedContext) {
        self.update_dashpay_profile_with(|user|
            user.update_with_public_message(public_message, context));
    }

    pub fn update_dashpay_profile_with_avatar_path(&self, avatar_url: String) {
        self.update_dashpay_profile_with_avatar_path_in_context(avatar_url, self.chain.platform_context())
    }

    pub fn update_dashpay_profile_with_avatar_path_in_context(&self, avatar_path: String, context: &ManagedContext) {
        self.update_dashpay_profile_with(|user|
            user.update_with_public_avatar_url(avatar_path, context));
    }

    pub fn update_dashpay_profile_with_display_name_and_public_message(&self, display_name: String, public_message: String) {
        self.update_dashpay_profile_with_display_name_and_public_message_in_context(display_name, public_message, self.chain.platform_context())
    }

    pub fn update_dashpay_profile_with_display_name_and_public_message_in_context(&self, display_name: String, public_message: String, context: &ManagedContext) {
        self.update_dashpay_profile_with(|user|
            user.update_with_display_name_and_public_message(display_name, public_message, context));
    }

    pub fn update_dashpay_profile_with_display_name_and_public_message_and_avatar_path(&self, display_name: String, public_message: String, avatar_path: String) {
        self.update_dashpay_profile_with_display_name_and_public_message_and_avatar_path_in_context(avatar_url, public_message, avatar_path, self.chain.platform_context())
    }

    pub fn update_dashpay_profile_with_display_name_and_public_message_and_avatar_path_in_context(&self, display_name: String, public_message: String, avatar_path: String, context: &ManagedContext) {
        self.update_dashpay_profile_with(|user|
            user.update_with_display_name_and_public_message_and_avatar_path(display_name, public_message, avatar_path, context));
    }

    // pub fn update_dashpay_profile_with_display_name_and_public_message_and_avatar_path_and_avatar_image_data(&self, display_name: String, public_message: String, avatar_path: String, avatar_image_data: Vec<u8>) {
    //     self.update_dashpay_profile_with_display_name_and_public_message_and_avatar_path_and_avatar_image_data_in_context(avatar_url, public_message, avatar_path, avatar_image_data, self.chain.platform_context())
    // }
    //
    // pub fn update_dashpay_profile_with_display_name_and_public_message_and_avatar_path_and_avatar_image_data_in_context(&self, display_name: String, public_message: String, avatar_path: String, avatar_image_data: Vec<u8>, context: &ManagedContext) {
    //     self.update_dashpay_profile_with(|user|
    //         user.update_with_display_name_and_public_message_and_avatar_path_and_avatar_image_data(display_name, public_message, avatar_path, avatar_image_data, context));
    // }

    // todo: avatar image hash and fingerprint

    pub fn update_dashpay_profile_with_display_name_and_public_message_and_avatar_path_and_hash_and_fingerprint(&self, display_name: String, public_message: String, avatar_path: String, avatar_hash: UInt256, avatar_fingerprint: u64) {
        self.update_dashpay_profile_with_display_name_and_public_message_and_avatar_path_and_hash_and_fingerprint_in_context(display_name, public_message, avatar_path, avatar_hash, avatar_fingerprint, self.chain.platform_context())
    }

    pub fn update_dashpay_profile_with_display_name_and_public_message_and_avatar_path_and_hash_and_fingerprint_in_context(&self, display_name: String, public_message: String, avatar_path: String, avatar_hash: UInt256, avatar_fingerprint: u64, context: &ManagedContext) {
        self.update_dashpay_profile_with(|user|
            user.update_with_display_name_and_public_message_and_avatar_path_and_hash_and_fingerprint(display_name, public_message, avatar_path, avatar_hash, avatar_fingerprint, context));
    }

    pub fn update_dashpay_profile_with_avatar_path_and_hash_and_fingerprint(&self, avatar_path: String, avatar_hash: UInt256, avatar_fingerprint: u64) {
        self.update_dashpay_profile_with_avatar_path_and_hash_and_fingerprint_in_context( avatar_path, avatar_hash, avatar_fingerprint, self.chain.platform_context())
    }

    pub fn update_dashpay_profile_with_avatar_path_and_hash_and_fingerprint_in_context(&self, avatar_path: String, avatar_hash: UInt256, avatar_fingerprint: u64, context: &ManagedContext) {
        self.update_dashpay_profile_with(|user|
            user.update_with_avatar_path_and_hash_and_fingerprint(avatar_path, avatar_hash, avatar_fingerprint, context));
    }

    pub fn signed_profile_document_transition_in_context(&mut self, context: &ManagedContext) -> Result<dyn ITransition, Error> {
        match self.profile_document_transition_in_context(context) {
            Some(transition) =>
                match self.sign_state_transition(&transition) {
                    Ok(true) => Ok(transition),
                    _ => Err(Error::DefaultWithCode(&format!("Transition failed to sign"), 500))
                },
            None => Err(Error::DefaultWithCode(&format!("Transition had nothing to update"), 500))
        }
    }

    pub fn sign_and_publish_profile(&mut self) -> Result<(bool, bool), Error> {
        self.sign_and_publish_profile_in_context(self.chain.platform_context())
    }
    pub fn sign_and_publish_profile_in_context(&mut self, context: &ManagedContext) -> Result<(bool, bool), Error> {
        match self.matching_dashpay_user_in_context(context) {
            Some(user) => match user.update_revision(context) {
                Ok(profile_document_revision) => {
                    match self.signed_profile_document_transition_in_context(context) {
                        Ok(transition) => {
                            match self.dapi_client().publish_transition(transition, context, &self.dispatch_context) {
                                Ok(success_dict) =>
                                    match user.update_remote_profile_revision(profile_document_revision, context) {
                                        Ok(updated) => Ok((true, false)),
                                        Err(err) => Err(Error::Default(&format!("can't update document revision")))
                                    },
                                Err(err) => DispatchContext::main_context().post(Err(err))
                            }
                        },
                        Err(err) => Err(err)
                    }
                },
                Err(err) => Err(Error::Default(&format!("can't update document revision")))
            },
            None => Err(Error::Default(&format!("no user in context")))
        }
    }

    /// Fetching
    pub fn fetch_profile(&mut self) -> Result<bool, Error> {
        self.dispatch_context.queue(|| self.fetch_profile_in_context(self.chain.platform_context(), &DispatchContext::main_context()))
    }

    pub fn fetch_profile_in_context(&mut self, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        self.fetch_profile_with_retry_count_in_context(DEFAULT_FETCH_PROFILE_RETRY_COUNT, context, dispatch_context)
    }

    pub fn fetch_profile_with_retry_count_in_context(&mut self, retry_count: u32, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        match self.internal_fetch_profile_in_context(context, dispatch_context) {
            Ok(true) => Ok(true),
            _ if retry_count > 0 => self.fetch_usernames_in_context_with_retry_count(context, dispatch_context, retry_count - 1),
            _ => Err(Error::Default(&format!("Fetching profile exceed retry count")))
        }
    }

    fn internal_fetch_profile_in_context(&mut self, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        let dashpay_contract = &self.chain.platform().dash_pay_contract;
        if dashpay_contract.state != ContractState::Registered {
            dispatch_context.post(Err(Error::DefaultWithCode(&format!("Dashpay Contract is not yet registered on network"), 500)))
        } else {
            match self.chain.identities_manager().fetch_profile_for_identity(self) {
                Ok((success, dashpayUserInfo)) => self.apply_profile_changes(dashpayUserInfo, false, context, &self.dispatch_context),
                Err(err) => dispatch_context.post(Err(err))
            }
        }
    }

    pub fn fetch_contact_requests(&mut self) -> Result<bool, Vec<Error>> {
        self.dispatch_context.queue(|| self.fetch_contact_requests_in_context(self.chain.platform_context(), &DispatchContext::main_context()))
    }

    pub fn fetch_contact_requests_in_context(&mut self, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        match self.fetch_incoming_contact_requests_in_context(context, &self.dispatch_context) {
            Ok(requests) => self.fetch_outgoing_contact_requests_in_context(context, dispatch_context),
            Err(err) => dispatch_context.post(Err(err))
        }
    }

    pub fn fetch_incoming_contact_requests(&mut self) -> Result<bool, Vec<Error>> {
        self.fetch_incoming_contact_requests_in_context(self.chain.platform_context(), &DispatchContext::main_context())
    }

    pub fn fetch_incoming_contact_requests_in_context(&mut self, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        self.fetch_incoming_contact_requests_with_params_in_context(None, DEFAULT_CONTACT_REQUEST_FETCH_RETRIES, context, dispatch_context)
    }

    pub fn fetch_incoming_contact_requests_with_params_in_context(&mut self, start_after: Option<Vec<u8>>, retries_left: u32, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        match self.internal_fetch_incoming_contact_requests_in_context(context, start_after, dispatch_context) {
            Ok((true, has_more_start_after)) if has_more_start_after.is_some() =>
                self.fetch_incoming_contact_requests_with_params_in_context(has_more_start_after, DEFAULT_CONTACT_REQUEST_FETCH_RETRIES, context, dispatch_context),
            Ok((success, _)) => Ok(success),
            _ if retries_left > 0 => self.fetch_incoming_contact_requests_with_params_in_context(start_after.clone(), retries_left - 1, context, dispatch_context),
            _ => Err(vec![Error::Default(&format!("Fetching incoming contact requests exceed retry count"))])
        }
    }

    fn internal_fetch_incoming_contact_requests_in_context(&mut self, context: &ManagedContext, start_after: Option<Vec<u8>>, dispatch_context: &DispatchContext) -> Result<(bool, Option<Vec<u8>>), Vec<Error>> {
        //DPContract *dashpayContract = [DSDashPlatform sharedInstanceForChain:self.chain].dashPayContract;
        let dashpay_contract = &self.chain.platform().dash_pay_contract;
        if dashpay_contract.state != ContractState::Registered {
            dispatch_context.post(Err(vec![Error::DefaultWithCode(&format!("The Dashpay contract is not properly set up"), 500)]))
        } else {
            match self.active_private_keys_are_loaded() {
                Ok(result) =>
                    self.dispatch_context.queue(|| match self.dapi_network_service().get_dashpay_incoming_contact_requests_for_user_id(&self.unique_id, cmp::max(self.last_checked_incoming_contacts_timestamp - HOUR_TIME_INTERVAL, 0), start_after, &self.dispatch_context) {
                        Ok(documents) => {
                            match self.handle_contact_request_objects(documents, context, &self.dispatch_context) {
                                Ok(success) => {
                                    let has_more = documents.len() == DAPI_DOCUMENT_RESPONSE_COUNT_LIMIT;
                                    if !has_more {

                                    }
                                },
                                Err(err)
                            }
                            [strongSelf handleContactRequestObjects:documents
                            context:context
                            completion:^(BOOL success, NSArray<NSError *> *errors) {
                                BOOL hasMore = documents.count == DAPI_DOCUMENT_RESPONSE_COUNT_LIMIT;
                                if (!hasMore) {
                                    [self.platformContext performBlockAndWait:^{
                                        self.lastCheckedIncomingContactsTimestamp = [[NSDate date] timeIntervalSince1970];
                                    }];
                                }
                                if (completion) {
                                    NSData * hasMoreStartAfter = documents.lastObject[@"$id"];
                                    dispatch_async(completionQueue, ^{
                                        completion(success, hasMoreStartAfter, errors);
                                    });
                                }
                            }
                            onCompletionQueue:self.identityQueue];

                        },
                        Err(err) => {

                        }
                    }),
                Err(err) => {
                    // The blockchain identity hasn't been intialized on the device, ask the user to activate the blockchain user,
                    // this action allows private keys to be cached on the blockchain identity level
                    // [NSError errorWithCode:500 localizedDescriptionKey:@"The blockchain identity hasn't yet been locally activated"]
                    return dispatch_context.post(Err(vec![err]));
                }
            }
        }

    }







    /// Handle an array of contact requests. This method will split contact requests into either incoming contact requests or outgoing contact requests and then call methods for handling them if applicable.
    /// @param rawContactRequests A dictionary of rawContactRequests, these are returned by the network.
    /// @param context The managed object context in which to process results.
    /// @param completion Completion callback with success boolean.
    pub fn handle_contact_request_objects(&self, contact_requests: Vec<ContactRequestJson>, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>>{
        assert_eq!(context, self.dispatch_context, "we should be on identity queue");
        let mut new_incoming_requests = Vec::<ContactRequest>::new();
        let mut new_outgoing_requests = Vec::<ContactRequest>::new();
        contact_requests.iter().for_each(|raw_contact| {
            let contact_request = ContactRequest::contact_request_from_dictionary(raw_contact, self);
            if contact_request.raw_contact.recipient_identity_unique_id == self.unique_id {
                if FriendRequestEntity::between_users_with_identity_ids(&contact_request.raw_contact.sender_identity_unique_id, &self.unique_id).is_err() {
                    new_incoming_requests.push(contact_request);
                }
            } else if contact_request.raw_contact.sender_identity_unique_id == self.unique_id {
                if FriendRequestEntity::between_users_with_identity_ids(&self.unique_id, &contact_request.raw_contact.recipient_identity_unique_id).is_err() {
                    new_outgoing_requests.push(contact_request);
                }
            } else {
                assert!(false, "the contact request needs to be either outgoing or incoming");
            }
        });

        // TODO: impl group request
        todo!()
        // __block BOOL succeeded = YES;
        // dispatch_group_t dispatchGroup = dispatch_group_create();
        //
        // if ([incomingNewRequests count]) {
        // dispatch_group_enter(dispatchGroup);
        // [self handleIncomingRequests:incomingNewRequests
        // context:context
        // completion:^(BOOL success, NSArray<NSError *> *errors) {
        // if (!success) {
        // succeeded = NO;
        // [rErrors addObjectsFromArray:errors];
        // }
        // dispatch_group_leave(dispatchGroup);
        // }
        // onCompletionQueue:completionQueue];
        // }
        // if ([outgoingNewRequests count]) {
        // dispatch_group_enter(dispatchGroup);
        // [self handleOutgoingRequests:outgoingNewRequests
        // context:context
        // completion:^(BOOL success, NSArray<NSError *> *errors) {
        // if (!success) {
        // succeeded = NO;
        // [rErrors addObjectsFromArray:errors];
        // }
        // dispatch_group_leave(dispatchGroup);
        // }
        // onCompletionQueue:completionQueue];
        // }
        //
        // dispatch_group_notify(dispatchGroup, completionQueue, ^{
        //     if (completion) {
        //         completion(succeeded, [rErrors copy]);
        //     }
        // });

    }


    pub fn handle_incoming_requests(&self, incoming_requests: Vec<ContactRequest>, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        if !self.is_active {
            return dispatch_context.post(Err(vec![Error::DefaultWithCode(&format!("Identity no longer active in wallet"), 410)]))
        }
        todo!()
    }


    pub fn add_friendship(&mut self, friendship: PotentialOneWayFriendship, context: &ManagedContext) -> Result<bool, Error> {

        FriendRequestEntity::

        DSFriendRequestEntity *friendRequestEntity = [DSFriendRequestEntity managedObjectInBlockedContext:context];
        friendRequestEntity.sourceContact = [friendship.sourceBlockchainIdentity matchingDashpayUserInContext:context];
        friendRequestEntity.destinationContact = [friendship.destinationBlockchainIdentity matchingDashpayUserInContext:context];
        friendRequestEntity.timestamp = friendship.createdAt;
        NSAssert(friendRequestEntity.sourceContact != friendRequestEntity.destinationContact, @"This must be different contacts");

        DSAccountEntity *accountEntity = [DSAccountEntity accountEntityForWalletUniqueID:self.wallet.uniqueIDString index:0 onChain:self.chain inContext:context];

        friendRequestEntity.account = accountEntity;

        [friendRequestEntity finalizeWithFriendshipIdentifier];
    }

    fn add_friendship_from_source_identity(&mut self, source_identity: &Identity, source_key_index: u32, recipient_identity: &Identity, recipient_key_index: u32, timestamp: u64, context: &ManagedContext) {
        // [context performBlockAndWait:^{
        let account = self.wallet.unwrap().account_with_number(0);
        let real_friendship = PotentialOneWayFriendship::init_with_destination_identity_created_at(
            recipient_identity,
            recipient_key_index,
            self,
            source_key_index,
            account,
            timestamp);

        // it was probably added already
        // this could happen when have 2 blockchain identities in same wallet
        // Identity A gets outgoing contacts
        // Which are the same as Identity B incoming contacts, no need to add the friendships twice
        match FriendRequestEntity::existing_friend_request_entity_with_source_identifier(&self.unique_id, &recipient_identity.unique_id, account.account_number, context) {
            Err(_) => self.add_friendship(real_friendship, context),
            _ => {}
        };
    }

    pub fn handle_outgoing_requests(&self, outgoing_requests: Vec<ContactRequest>, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Vec<Error>> {
        todo!()
    }

    fn add_incoming_request_from_contact(&self, user_entity: &FriendRequestAggregate, extended_public_key: &dyn IKey, timestamp: u64) {


        DSFriendRequestEntity *friendRequestEntity = [DSFriendRequestEntity managedObjectInBlockedContext:context];
        friendRequestEntity.sourceContact = dashpayUserEntity;
        friendRequestEntity.destinationContact = [self matchingDashpayUserInContext:dashpayUserEntity.managedObjectContext];
        friendRequestEntity.timestamp = timestamp;
        todo!()
    }

    fn save_initial(&self) {
        self.save_initial_in_context(self.chain.platform_context());
    }

    fn initial_entity_in_context(&self, context: &ManagedContext) -> IdentityEntity {
        todo!()
    }

    fn save_initial_in_context(&self, context: &ManagedContext) {
        if self.is_transient {
            return;
        }
        // no need for active check, in fact it will cause an infinite loop
        let entity = self.initial_entity_in_context(context);
        match UserEntity::get_by_identity_unique_id(&self.unique_id, context) {
            Ok(user) => {
                self.matc
            },
            Err(err) => println!("User not found")
        }
        // [context performBlockAndWait:^{
        //     DSBlockchainIdentityEntity *entity = [self initialEntityInContext:context];
        //     DSDashpayUserEntity *dashpayUserEntity = entity.matchingDashpayUser;
        //
        //     [context ds_saveInBlockAndWait];
        //     [[NSManagedObjectContext viewContext] performBlockAndWait:^{
        //         self.matchingDashpayUserInViewContext = [[NSManagedObjectContext viewContext] objectWithID:dashpayUserEntity.objectID];
        //     }];
        //     [[NSManagedObjectContext platformContext] performBlockAndWait:^{
        //         self.matchingDashpayUserInPlatformContext = [[NSManagedObjectContext platformContext] objectWithID:dashpayUserEntity.objectID];
        //     }];
        //     if ([self isLocal]) {
        //     dispatch_async(dispatch_get_main_queue(), ^{
        //     [[NSNotificationCenter defaultCenter] postNotificationName:DSBlockchainIdentityDidUpdateNotification object:nil userInfo:@{DSChainManagerNotificationChainKey: self.chain, DSBlockchainIdentityKey: self}];
        //     });
        //     }
        // }];

    }

    pub fn save_in_context(&self, context: &ManagedContext {
        if self.is_transient || !self.is_active {
            return;
        }
        match IdentityEntity::update_if_needed(self, context) {
            Ok(events) if !events.is_empty() =>
                DispatchContext::main_context().queue(|| NotificationCenter::post(Notification::IdentityDidUpdate(self.chain, self, Some(&events)))),
            _ => {}
        }
    }

    fn identifier_for_key_at_path(&self, index_path: &IndexPath<u32>, derivation_path: &mut dyn IDerivationPath) -> String {
        let softened_path = index_path.soften_all_items();
        // TODO check correctness
        format!("{}-{:?}-{}",
                base58::encode_slice(self.unique_id.as_bytes()),
                derivation_path.standalone_extended_public_key_unique_id(),
                softened_path.index_path_string())
    }

    pub fn create_new_key_for_entity<T: AsBytesVec>(&self, key: &dyn IKey, entity: &IdentityEntity, index_path: &IndexPath<T>, status: &KeyStatus, mut derivation_path: &dyn IDerivationPath, context: &ManagedContext) -> Option<NewIdentityKeyPathEntity> {
        match DerivationPathEntity::derivation_path_entity_matching_derivation_path(derivation_path, context) {
            Ok(derivation_path_entity) => {
                match IdentityKeyPathEntity::count_key_paths_for(entity.id, derivation_path_entity.id, &index_path.as_bytes_vec(), context) {
                    Ok(0) => {
                        let new_key_path_entity = NewIdentityKeyPathEntity {
                            key_id: index_path.indexes.last().unwrap().clone() as i32,
                            key_status: status.into(),
                            key_type: key.r#type().into(),
                            public_key: key.public_key_data().clone(),
                            path: index_path.as_bytes_vec().clone(),
                            identity_id: entity.id,
                            derivation_path_id: Some(derivation_path_entity.id),
                        };
                        if let Some(private_key_data) = key.private_key_data() {
                            Keychain::set_data(self.identifier_for_key_at_path(index_path, &mut derivation_path), Some(private_key_data), true)
                                .expect("Keychain should be able to store private key data");
                        } else {
                            let private_key = self.derive_private_key_at_index_path(index_path, key.r#type());
                            assert!(private_key.is_some() && private_key.unwrap().public_key_data().eq(key.public_key_data()), "The keys don't seem to match up");
                            let private_key_data = private_key.unwrap().private_key_data();
                            assert!(private_key_data.is_some(), "Private key data should exist");
                            Keychain::set_data(self.identifier_for_key_at_path(index_path, &mut derivation_path), private_key_data, true)
                                .expect("Keychain should be able to store private key data");
                        }
                        Some(new_key_path_entity)
                    },
                    _ => {
                        println!("Already had saved this key {}", "<REDACTED>");
                        return None;
                    }
                }

            },
            Err(err) => {
                println!("create_new_key_for_entity error: {:?}", err);
                return None;
            }
        }
    }

    pub fn save_new_key<T: AsBytesVec>(&self, key: &dyn IKey, index_path: &IndexPath<T>, status: &KeyStatus, mut derivation_path: &dyn IDerivationPath, context: &ManagedContext) {
        assert!(self.is_local, "This should only be called on local blockchain identities");
        if !self.is_local || self.is_transient || !self.is_active {
            return;
        }
        if let Some(identity_entity) = self.identity_entity_in_context(context) {
            if let Some(key_path_entity) = self.create_new_key_for_entity(key, &identity_entity, index_path, status, derivation_path, context) {
                match IdentityKeyPathEntity::create(&key_path_entity, context) {
                    Ok(..) => println!("New key path entity saved"),
                    Err(err) => println!("Can't save new key path entity {:?}", err)
                }
            }
        }
        DispatchContext::main_context()
            .queue(||
                NotificationCenter::post(
                    Notification::IdentityDidUpdate(
                        self.chain,
                        self,
                        Some(&vec![DSBlockchainIdentityUpdateEventKeyUpdate]))));
    }

    pub fn save_new_remote_identity_key(&self, key: &dyn IKey, key_id: u32, status: &KeyStatus, context: &ManagedContext) {
        assert!(!self.is_local, "This should only be called on non local blockchain identities");
        if self.is_local || self.is_transient || !self.is_active {
            return;
        }
        if let Some(entity) = self.identity_entity_in_context(context) {
            if let Some(0) = IdentityKeyPathEntity::count_key_paths_with_key_id(entity.id, key_id as i32, context) {
                let new_key_path_entity = NewIdentityKeyPathEntity {
                    key_id: key_id as i32,
                    key_status: status.into(),
                    key_type: key.r#type().into(),
                    public_key: key.public_key_data().clone(),
                    identity_id: entity.id,
                    ..Default::default()
                };
                match IdentityKeyPathEntity::create(&key_path_entity, context) {
                    Ok(..) => println!("New key path entity saved"),
                    Err(err) => println!("Can't save new key path entity {:?}", err)
                }
            }
            DispatchContext::main_context()
                .queue(||
                    NotificationCenter::post(
                        Notification::IdentityDidUpdate(
                            self.chain,
                            self,
                            Some(&vec![DSBlockchainIdentityUpdateEventKeyUpdate]))));
        }
    }

    pub fn update_status_for_key_at_path<T: AsBytesVec>(&self, status: &KeyStatus, index_path: IndexPath<T>, derivation_path: &dyn IDerivationPath, context: &ManagedContext) {
        assert!(self.is_local, "This should only be called on local blockchain identities");
        if !self.is_local || self.is_transient || !self.is_active {
            return;
        }
        if let Some(entity) = self.identity_entity_in_context(context) {
            match DerivationPathEntity::derivation_path_entity_matching_derivation_path(derivation_path, context) {
                Ok(derivation_path_entity) => {
                    match IdentityKeyPathEntity::get_by_identity_id_and_path(entity.id, derivation_path_entity.id, &index_path.as_bytes_vec(), context) {
                        Ok(key_path_entity) if key_path_entity.key_status != status.into() => {
                            let _updated = key_path_entity.update_key_status(status.into(), context);
                        },
                        _ => {}
                    }
                    DispatchContext::main_context()
                        .queue(||
                            NotificationCenter::post(
                                Notification::IdentityDidUpdate(
                                    self.chain,
                                    self,
                                    Some(&vec![DSBlockchainIdentityUpdateEventKeyUpdate]))));
                },
                Err(err) => println!("")
            }
        }
    }
    pub fn update_status_for_key_with_index_id(&self, status: &KeyStatus, key_id: u32, context: &ManagedContext) {
        assert!(!self.is_local, "This should only be called on non local blockchain identities");
        if self.is_local || self.is_transient || !self.is_active {
            return;
        }
        if let Some(entity) = self.identity_entity_in_context(context) {
            if let Some(key_path_entity) = IdentityKeyPathEntity::get_by_identity_id_and_key_id(entity.id, key_id as i32, context) {
                let _updated = key_path_entity.update_key_status(status.into(), context);
                DispatchContext::main_context()
                    .queue(||
                        NotificationCenter::post(
                            Notification::IdentityDidUpdate(
                                self.chain,
                                self,
                                Some(&vec![DSBlockchainIdentityUpdateEventKeyUpdate]))));
            }
        }
    }

    fn get_statuses_dict(&self, username_full_paths: &Vec<String>) -> HashMap<String, HashMap<String, UsernameInfoKind>> {
        self.username_statuses
            .into_iter()
            .filter(|(key, _)| username_full_paths.contains(key))
            .collect()
    }

    pub fn save_new_username(&mut self, username: &String, domain: &String, status: &UsernameStatus, context: &ManagedContext) {
        assert!(!username.contains("."), "This is most likely an error");
        assert!(!domain.is_empty(), "Domain must be exist");
        if self.is_transient || !self.is_active {
            return;
        }
        let salt = self.salt_for_username_full_path(&Self::full_path_for_username(username, domain), false, context);
        match IdentityEntity::save_new_username(&self.unique_id, username, domain, status, salt.clone(), context) {
            Ok(_) => NotificationCenter::post(Notification::IdentityDidUpdateUsernameStatus {
                chain: self.chain,
                identity: self,
                username,
                domain,
                status
            }),
            Err(err) => println!("save_new_username error: {}", err)
        }
    }

    pub fn set_username_full_paths(&mut self, username_full_paths: &Vec<String>, status: &UsernameStatus) {
        username_full_paths
            .iter()
            .for_each(|&username_full_path| {
                self.username_statuses
                    .entry(username_full_path)
                    .or_insert(HashMap::new())
                    .insert(BLOCKCHAIN_USERNAME_STATUS.to_string(), UsernameInfoKind::UsernameStatus(status));
            })
    }

    fn set_and_save_username_full_paths(&mut self, username_full_paths: &Vec<String>, status: &UsernameStatus, context: &ManagedContext) {
        self.set_username_full_paths(username_full_paths, status);
        self.save_usernames_in_dictionary(self.get_statuses_dict(username_full_paths), status, context);
    }

    fn save_username_full_paths(&mut self, username_full_paths: &Vec<String>, status: &UsernameStatus, context: &ManagedContext) {
        self.save_usernames_in_dictionary(self.get_statuses_dict(username_full_paths), status, context);
    }

    fn save_usernames_in_dictionary(&mut self, full_path_usernames_dictionary: HashMap<String, HashMap<String, UsernameInfoKind>>, status: &UsernameStatus, context: &ManagedContext) {
        if !self.is_transient && self.is_active {
            full_path_usernames_dictionary.values().for_each(|dict|
                match (dict.get(&BLOCKCHAIN_USERNAME_PROPER), dict.get(&BLOCKCHAIN_USERNAME_DOMAIN)) {
                    (Some(UsernameInfoKind::UsernameProper(username)), Some(UsernameInfoKind::UsernameDomain(domain))) =>
                        self.save_username(username, domain, status, None, false, context),
                    _ => ()
                });
        }
    }

    fn save_username_full_path(&mut self, username_full_path: &String, status: &UsernameStatus, salt: Option<&UInt256>, commit_save: bool, context: &ManagedContext) {
        if self.is_transient && !self.is_active {
            return;
        }
        match IdentityEntity::save_username_full_path(&self.unique_id, username_full_path, status, salt, context) {
            Ok(IdentityUsernameEntity { string_value, domain, .. }) =>
                DispatchContext::main_context().queue(|| NotificationCenter::post(Notification::IdentityDidUpdateUsernameStatus {
                    chain: self.chain,
                    identity: &self,
                    username: &string_value,
                    domain: &domain,
                    status
                })),
            Err(err) => println!("Identity.save_username_full_path: error {}", err)
        }
    }
    fn save_username_in_domain(&mut self, username: &String, domain: &String, status: &UsernameStatus, salt: Option<&UInt256>, commit_save: bool, context: &ManagedContext) {
        if self.is_transient && !self.is_active {
            return;
        }
        match IdentityEntity::save_username_in_domain(&self.unique_id, username, domain, status, salt, context) {
            Ok(..) =>
                DispatchContext::main_context().queue(||
                    NotificationCenter::post(Notification::IdentityDidUpdateUsernameStatus {
                        chain: self.chain,
                        identity: &self,
                        username,
                        domain,
                        status
                    })),
            Err(err) => println!("Identity.save_username_in_domain: error {}", err)
        }
    }

    pub(crate) fn delete_persistent_object_and_save(&self, save: bool, context: &ManagedContext) {
        if let Some(wallet) = self.wallet {
            match IdentityEntity::delete_identity_for_wallet(&self.unique_id, wallet, context) {
                Ok(_deleted @ 1) =>
                    DispatchContext::main_context().queue(||
                        NotificationCenter::post(
                            Notification::IdentityDidUpdate(self.chain, self, None))),
                Ok(..) => println!("Identity.delete_persistent_object_and_save: not deleted"),
                Err(err) => println!("Identity.delete_persistent_object_and_save: error {}", err)
            }
        }
    }

    fn identity_entity(&self) -> QueryResult<IdentityEntity> {
        self.identity_entity_in_context(self.chain.view_context())
    }

    fn identity_entity_in_context(&self, context: &ManagedContext) -> QueryResult<IdentityEntity> {
        IdentityEntity::identity_with_unique_id(&self.unique_id, context)
    }





    pub fn matching_dashpay_user_in_view_context(&self) -> Option<UserEntity> {
        self.matching_dashpay_user_in_context(self.chain.view_context())
    }

    pub fn matching_dashpay_user_in_platform_context(&self) -> Option<UserEntity> {
        self.matching_dashpay_user_in_context(self.chain.platform_context())
    }

    pub fn matching_dashpay_user_in_context(&self, context: &ManagedContext) -> Option<UserEntity> {
        todo!()
    }


    /// Response Processing
    pub fn apply_profile_changes(&self, user: &TransientUser, save_context: bool, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<bool, Error> {
        todo!()
    }

    pub fn active_private_keys_are_loaded(&self) -> Result<bool, Error> {
        let mut loaded = true;
        for (&index, key_dictionary) in &self.key_info_dictionaries {
            match (key_dictionary.get(&KeyDictionary::KeyStatus), key_dictionary.get(&KeyDictionary::KeyType)) {
                (Some(KeyStatus::Registered), Some(key_type)) => {
                    match self.has_private_key_at_index(index, key_type as &KeyType) {
                        Ok(has_index) => {
                            loaded &= has_index;
                        },
                        Err(err) => { return Err(err); }
                    }
                },
                _ => { return Err(Error::Default(&format!("key_info_dictionaries has malformed fields"))); }
            }
        }
        Ok(loaded)
    }

}
