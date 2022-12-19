use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::SystemTime;
use byte::BytesExt;
use crate::derivation::incoming_funds_derivation_path::IncomingFundsDerivationPath;
use crate::platform::identity::identity::Identity;
use crate::chain::wallet::account::Account;
use crate::crypto::byte_util::{Reversable, Zeroable};
use crate::crypto::UInt256;
use crate::derivation::derivation_path::{Error, IDerivationPath};
use crate::keys::key::IKey;
use crate::platform::base::serializable_object::{SerializableKey, SerializableValue};
use crate::platform::document::{Document, Protocol};
use crate::platform::document::protocol::TableName;
use crate::platform::identity::potential_contact::PotentialContact;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::friend_request::{FriendRequestAggregate, FriendRequestEntity, NewFriendRequestEntity};
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::account::user::UserEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::util::time::TimeUtil;

pub struct PotentialOneWayFriendship {
    pub account: &'static Account,
    pub destination_identity: &'static Identity,
    /// this is the holder of the contacts, not the destination
    pub source_identity: &'static Identity,
    pub created_at: u64,
    pub funds_derivation_path_for_contact: Option<IncomingFundsDerivationPath>,
    pub source_key_index: u32,
    pub destination_key_index: u32,
    pub destination_contact: Option<PotentialContact>,
    extended_public_key: Option<dyn IKey>,
    encrypted_extended_public_key_data: Option<&'static Vec<u8>>,
}

impl PotentialOneWayFriendship {

    pub(crate) fn init_with_destination_identity(destination_identity: &Identity, destination_key_index: u32, source_identity: &Identity, source_key_index: u32, account: &Account) -> Self {
        Self::init_with_destination_identity_created_at(destination_identity, destination_key_index, source_identity, source_key_index, account, SystemTime::seconds_since_1970())
    }

    pub(crate) fn init_with_destination_identity_created_at(destination_identity: &Identity, destination_key_index: u32, source_identity: &Identity, source_key_index: u32, account: &Account, created_at: u64,) -> Self {
        Self {
            account,
            destination_identity,
            source_identity,
            created_at,
            source_key_index,
            destination_key_index,
            ..Default::default()
        }
    }

    pub fn destination_identity_unique_id(&self) -> &UInt256 {
        &self.destination_identity.unique_id
        /*if let Some(destination) = self.destination_identity {
            &self.destination_identity.unique_id
        } else if let Some(destination_contact) = self.destination_contact {
            &destination_contact.associated_identity_unique_id
        } else {
            UInt256::MIN
        }*/
    }

    pub fn source_key_at_index(&self) -> Option<&dyn IKey> {
        assert!(self.source_identity, "The source identity should be present");
        self.source_identity.key_at_index(self.source_key_index)
    }

    pub fn destination_key_at_index(&self) -> Option<&dyn IKey> {
        self.destination_identity.key_at_index(self.destination_key_index)
        /*if let Some(destination_identity) = self.destination_identity {
            self.destination_identity.key_at_index(self.destination_key_index)
        } else if let Some(destination_contact) = &self.destination_contact {
            destination_contact.public_key_at_index(self.destination_key_index)
        } else {
            None
        }*/
    }

    pub fn derivation_path(&self) -> IncomingFundsDerivationPath {
        assert!(!self.destination_identity_unique_id().is_zero(), "destinationBlockchainIdentityUniqueId must not be null");
        let path = IncomingFundsDerivationPath::contact_based_derivation_path_with_destination_identity_unique_id(
            self.destination_identity_unique_id().clone(),
            self.source_identity.unique_id,
            self.account.account_number,
            self.source_identity.wallet.unwrap().chain);
        path.account = self.account;
        path
    }

    pub fn create_derivation_path_and_save_extended_public_key(&mut self) -> &IncomingFundsDerivationPath {
        assert!(!self.destination_identity_unique_id().is_zero(), "destinationBlockchainIdentityUniqueId must not be null");
        let path = self.derivation_path();
        self.funds_derivation_path_for_contact = Some(path);
        let master_contacts_derivation_path = self.account.master_contacts_derivation_path;
        self.extended_public_key = path.generate_extended_public_key_from_parent_derivation_path(master_contacts_derivation_path, None);
        &path
    }

    pub fn encrypt_extended_public_key(&mut self) -> Result<bool, Error> {
        assert!(self.extended_public_key.is_some(), "Problem creating extended public key for potential contact?");
        let recipient_key = self.destination_key_at_index();
        match self.source_identity.encrypt_data(self.extended_public_key.unwrap().extended_public_key_data(), self.source_key_index, recipient_key) {
            Ok(encrypted_data) => {
                self.encrypted_extended_public_key_data = Some(encrypted_data);
                Ok(true)
            },
            Err(err) => Ok(false)
        }
    }
    pub fn create_account_reference(&self) -> u32 {
        let key = self.source_key_at_index().unwrap();
        let account_secret_key = key.hmac_256_data(self.extended_public_key.unwrap().extended_public_key_data()).reversed();
        let account_secret_key28 = account_secret_key.0.read_with::<u32>(&mut 0, byte::LE).unwrap() >> 4;
        let shortened_account_bits = self.account.account_number & 0x0FFFFFFF;
        let version = 0; // currently set to 0
        let version_bits = version << 28;
        // this is the account ref
        version_bits | (account_secret_key28 ^ shortened_account_bits)
    }

    pub fn contact_request_document_with_entropy(&self, entropy: &UInt256) -> Document {
        assert!(!self.destination_identity_unique_id().is_zero(), "the destination contact's associatedBlockchainIdentityUniqueId must be set before making a friend request");
        assert!(self.encrypted_extended_public_key_data.is_some() && !self.encrypted_extended_public_key_data.unwrap().is_empty(), "The encrypted extended public key must exist");
        assert!(self.extended_public_key.is_some(), "Problem creating extended public key for potential contact?");
        let data = HashMap::<dyn SerializableKey, dyn SerializableValue>::from([
            ("$createdAt", self.created_at * 1000),
            ("toUserId", self.destination_identity_unique_id()),
            ("encryptedPublicKey", self.encrypted_extended_public_key_data.unwrap()),
            ("sender_key_index", self.source_key_index),
            ("recipient_key_index", self.destination_key_index),
            ("account_reference", self.create_account_reference())
        ]);
        let contact = self.source_identity.dashpay_document_factory().document_on_table_using_entropy(TableName::ContactRequest, Some(data), entropy);
        assert!(contact.is_ok(), "Failed to build a contact");
        contact.unwrap()
    }

    pub fn store_extended_public_key_associated_with_friend_request_in_context(&self, friend_request_entity: FriendRequestAggregate, context: &ManagedContext) -> DerivationPathEntity {
        self.funds_derivation_path_for_contact.unwrap().store_extended_public_key_under_wallet_unique_id(self.account.wallet.unwrap().unique_id_string);
        DerivationPathEntity::derivationPathEntityMatchingDerivationPath(self.funds_derivation_path_for_contact.unwrap().associate_with_friend_request(friend_request_entity), context)
    }
    pub fn store_extended_public_key_associated_with_friend_request(&self, friend_request_entity: FriendRequestAggregate) -> DerivationPathEntity {
        self.store_extended_public_key_associated_with_friend_request_in_context(friend_request_entity, &friend_request_entity.context)
    }

    pub fn outgoingFriendRequestForDashpayUserEntity(&self, user_entity: &UserEntity, associated_identity_entity: &IdentityEntity, timestamp: u64) -> FriendRequestAggregate {
        assert_eq!(associated_identity_entity.unique_id, self.destination_identity_unique_id(), "contact entity must match");
        assert!(self.source_identity.matching_dashpay_user_in_view_context().is_some(), "The own contact of the source Identity must be set");
        let path = DerivationPathEntity::derivationPathEntityMatchingDerivationPath(self.funds_derivation_path_for_contact.unwrap(),)
        let friendRequestEntity = NewFriendRequestEntity {
            account_id: 0,
            source_key_index: 0,
            destination_key_index: 0,
            source_contact_id: 0,
            destination_contact_id: 0,
            derivation_path_id: 0,
            timestamp: Default::default(),
            friendship_identifier: Default::default()
        };
        let friendRequestEntity = FriendRequestEntity::create_and_get()
        DSFriendRequestEntity *friendRequestEntity = [DSFriendRequestEntity managedObjectInBlockedContext:dashpayUserEntity.managedObjectContext];
        friendRequestEntity.sourceContact = [self.sourceBlockchainIdentity matchingDashpayUserInContext:friendRequestEntity.managedObjectContext];
        friendRequestEntity.destinationContact = dashpayUserEntity;
        NSAssert(friendRequestEntity.sourceContact != friendRequestEntity.destinationContact, @"This must be different contacts");
        friendRequestEntity.derivationPath = [DSDerivationPathEntity derivationPathEntityMatchingDerivationPath:self.fundsDerivationPathForContact inContext:dashpayUserEntity.managedObjectContext];
        NSAssert(friendRequestEntity.derivationPath, @"There must be a derivation path");
        friendRequestEntity.account = friendRequestEntity.derivationPath.account;
        friendRequestEntity.timestamp = timestamp;

        [friendRequestEntity finalizeWithFriendshipIdentifier];
        return friendRequestEntity;

    }


}

impl PartialEq for PotentialOneWayFriendship {
    fn eq(&self, other: &Self) -> bool {
        self == other || (self.destination_identity.unique_id == other.destination_identity.unique_id &&
            self.source_identity.unique_id == other.source_identity.unique_id &&
            self.account.account_number == other.account.account_number)
    }
}

impl Hash for PotentialOneWayFriendship {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.destination_identity.hash);
        state.write(self.source_identity.hash);
        state.write(self.account.account_number.to_le_bytes());

        //return self.destinationBlockchainIdentity.hash ^ self.sourceBlockchainIdentity.hash ^ self.account.accountNumber;
    }
}
