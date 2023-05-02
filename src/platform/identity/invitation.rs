use std::collections::HashMap;
use diesel::{ExpressionMethods, QueryResult};
use hashes::hex::{FromHex, ToHex};
use url::Url;
use crate::chain::chain::Chain;
use crate::chain::dispatch_context::{DispatchContext, DispatchContextType};
use crate::chain::ext::derivation::Derivation;
use crate::chain::ext::settings::Settings;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::tx::TransactionType;
use crate::chain::wallet::constants::{DSBlockchainInvitationUpdateEventLink, DSBlockchainInvitationUpdateEvents};
use crate::chain::wallet::extension::invitations::WalletInvitations;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::byte_util::{Reversable, Zeroable};
use crate::crypto::UInt256;
use crate::crypto::UTXO;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::notifications::{Notification, NotificationCenter};
use crate::platform::identity::identity::Identity;
use crate::platform::identity::registration_step::RegistrationStep;
use crate::schema::invitations;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::account::invitation::InvitationEntity;
use crate::storage::models::entity::{Entity, EntityUpdates};
use crate::util;

pub type VerifyInvitationLinkCallback = fn(dyn ITransaction, bool, util::Error);

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Invitation {
    /// This is the identity that was made from the invitation.
    /// There should always be an identity associated to a blockchain invitation.
    /// This identity might not yet be registered on Dash Platform.
    pub identity: &'static Identity,
    /// This is an invitation that was created locally.
    pub created_locally: bool,
    /// This is an invitation that was created with an external link, and has not yet retrieved the identity.
    pub needs_identity_retrieval: bool,
    /// This is the wallet holding the blockchain invitation. There should always be a wallet associated to a blockchain invitation.
    pub wallet: &'static Wallet,
    /// A name for locally created invitation.
    pub name: Option<String>,
    /// A tag for locally created invitation.
    pub tag: Option<String>,
    pub link: Option<String>,

    pub is_transient: bool,

    pub chain: &'static Chain,
}

impl Invitation {

    fn local_with_wallet_and_identity(wallet: &Wallet, identity: &Identity) -> Self {
        Self {
            wallet,
            identity,
            chain: wallet.chain,
            created_locally: true,
            ..Default::default()
        }
    }

    pub fn init_at_index(index: u32, wallet: &Wallet) -> Self {
        let mut identity = &Identity::init_at(index, wallet);
        let s = Self::local_with_wallet_and_identity(wallet, identity);
        identity.set_associated_invitation(&s);
        s
    }


    pub fn init_at_with_funding_transaction(index: u32, transaction: &CreditFundingTransaction, wallet: &Wallet) -> Self {
        //this is the creation of a new blockchain identity
        let mut identity = &Identity::init_at_with_credit_funding_transaction_and_username_dictionary(index, transaction, None, wallet);
        let s = Self::local_with_wallet_and_identity(wallet, identity);
        identity.set_associated_invitation(&s);
        s
    }

    pub fn init_at_index_with_locked_outpoint(index: u32, locked_outpoint: &UTXO, wallet: &Wallet) -> Self {
        assert_ne!(index, u32::MAX, "index must be found");
        let mut identity = &Identity::init_at_with_locked_outpoint(index, locked_outpoint, wallet);
        let s = Self::local_with_wallet_and_identity(wallet, identity);
        identity.set_associated_invitation(&s);
        s
    }

    pub fn init_at_index_with_locked_outpoint_and_invitation_entity(index: u32, locked_outpoint: &UTXO, wallet: &Wallet, entity: &InvitationEntity) -> Self {
        let mut identity = &Identity::init_at_with_locked_outpoint_and_entity(index, locked_outpoint, wallet, &entity.get_identity());
        let mut s = Self::local_with_wallet_and_identity(wallet, identity);
        s.link = entity.link.clone();
        s.name = entity.name.clone();
        s.tag = entity.tag.clone();
        identity.set_associated_invitation(&s);
        s
    }

    pub fn init_at_index_with_locked_outpoint_and_identity_entity_and_invitation_entity(index: u32, locked_outpoint: UTXO, wallet: &Wallet, identity_entity: &IdentityEntity, entity: &InvitationEntity) -> Self {
        let mut identity = &Identity::init_at_with_locked_outpoint_and_entity(index, &locked_outpoint, wallet, identity_entity);
        let mut s = Self::local_with_wallet_and_identity(wallet, identity);
        s.link = entity.link.clone();
        s.name = entity.name.clone();
        s.tag = entity.tag.clone();
        identity.set_associated_invitation(&s);
        s
    }

    pub fn init_with_invitation_link(link: String, wallet: &Wallet) -> Self {
        Self {
            wallet,
            chain: wallet.chain,
            link: Some(link),
            needs_identity_retrieval: true,
            ..Default::default()
        }
    }



    pub fn register_in_wallet_for_registration_funding_transaction(&mut self, mut transaction: &CreditFundingTransaction) {
        // assert!(self.identity , "The identity must already exist");
        self.identity.set_invitation_registration_credit_funding_transaction(transaction);
        self.register_in_wallet_for_blockchain_identity_unique_id(&transaction.credit_burn_identity_identifier());
        // we need to also set the address of the funding transaction to being used so future identities past the initial gap limit are found
        transaction.mark_invitation_address_as_used_in_wallet(self.wallet);
    }

    pub fn register_in_wallet_for_blockchain_identity_unique_id(&mut self, unique_id: &UInt256) {
        self.identity.set_invitation_unique_id(unique_id);
        self.register_in_wallet();
    }


    pub fn is_registered_in_wallet(&self) -> bool {
        self.wallet.contains_blockchain_invitation(self)
    }

    pub fn register_in_wallet(&mut self) {
        assert!(self.identity.is_outgoing_invitation, "The underlying identity is not from an invitation");
        if !self.identity.is_outgoing_invitation { return; }
        self.wallet.register_invitation(self);
        self.identity.save_initial();
        DispatchContext::main_context().queue(||
            NotificationCenter::post(Notification::InvitationDidUpdate(self.chain, self)));
    }


    pub fn update_in_wallet(&self) {
        self.save_in_context(self.chain.platform_context());
    }

    pub fn unregister_locally(&mut self) -> bool {
        assert!(self.identity.is_outgoing_invitation, "The underlying identity is not from an invitation");
        if !self.identity.is_outgoing_invitation || self.identity.is_registered {
            // if the invitation has already been used we can not unregister it
            return false;
        }
        self.wallet.unregister_invitation(self);
        self.delete_persistent_object_and_save(true, self.chain.platform_context());
        true
    }

    // pub async fn verify_invitation_link(&self, dispatch_context: &DispatchContext) -> Result<&dyn ITransaction, util::Error> {
    //     Self::verify_invitation_link_with_completion(&self.link.unwrap(), self.wallet.chain, dispatch_context)
    // }
    //
    // pub async fn verify_invitation_link_with_completion(link: &String, chain: &Chain, dispatch_context: &DispatchContext) -> Result<&dyn ITransaction, util::Error> {
    //     match Url::parse(link.as_str()) {
    //         Err(err) => Err(util::Error::Default(&err.to_string())),
    //         Ok(url) => {
    //             let mut asset_lock_tx_hash = UInt256::MIN;
    //             let mut funding_private_key: Option<ECDSAKey> = None;
    //             url.query_pairs().for_each(|pair| {
    //                 match pair {
    //                     (Cow::Borrowed("assetlocktx"), Cow::Borrowed(val)) => {
    //                         asset_lock_tx_hash = UInt256::from_hex(val).unwrap();
    //                     },
    //                     (Cow::Borrowed("pk"), Cow::Borrowed(val)) => {
    //                         funding_private_key = ECDSAKey::init_with_private_key(&val.to_string(), chain);
    //                     }
    //                     _ => {}
    //                 }
    //             });
    //             if asset_lock_tx_hash.is_zero() {
    //                 Err(util::Error::DefaultWithCode(&format!("Invitation format is not valid"), 400))
    //             } else {
    //                 match funding_private_key {
    //                     // !if key.seckey.is_zero()
    //                     Some(key) =>
    //                         match chain.dapi_client().core_service.get_transaction_with_hash(&asset_lock_tx_hash, dispatch_context).await {
    //                             Ok(transaction) if transaction.r#type() == TransactionType::CreditFunding => Ok(transaction),
    //                             _ => Err(util::Error::DefaultWithCode(&format!("Invitation format is not valid"), 400))
    //                         },
    //                     _ => Err(util::Error::DefaultWithCode(&format!("Invitation transaction is not valid"), 400))
    //                 }
    //             }
    //         }
    //     }
    // }

    pub async fn accept_invitation_using_wallet_index(&mut self, index: u32, dashpay_username: String, authprompt: String, registration_steps: RegistrationStep, step_completion: fn(RegistrationStep), dispatch_context: &DispatchContext) -> Result<RegistrationStep, util::Error> {
        match Url::parse(self.link.clone().unwrap().as_str()) {
            Err(err) => Err(err.into()),
            Ok(url) => {
                let query_pairs = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
                let asset_lock_tx_hash = match query_pairs.get("assetlocktx") {
                    Some(s) => UInt256::from_hex(s).unwrap_or(UInt256::MIN),
                    _ => UInt256::MIN,
                };
                let funding_private_key = match query_pairs.get("pk") {
                    Some(private_key_string) => ECDSAKey::init_with_private_key(private_key_string, self.chain),
                    _ => None
                };
                if asset_lock_tx_hash.is_zero() {
                    Err(util::Error::DefaultWithCode(format!("Invitation format is not valid"), 400))
                } else {
                    match funding_private_key {
                        // !if key.seckey.is_zero()
                        Some(key) =>
                            match self.chain.dapi_client().core_service.get_transaction_with_hash(&asset_lock_tx_hash, dispatch_context).await {
                                Ok(transaction) if transaction.r#type() == TransactionType::CreditFunding => {
                                    let mut identity = transaction.associate_with_accepted_invitation(self, index, dashpay_username, self.wallet);
                                    self.identity = &identity;
                                    let success = identity.set_external_funding_private_key(key);
                                    if success {
                                        match identity.generate_identity_extended_public_keys_with_prompt(authprompt).await {
                                            Ok(true) => identity.continue_registering_identity_on_network(registration_steps, RegistrationStep::L1Steps, step_completion),
                                            _ => Err(util::Error::DefaultWithCode(format!("Error generating Identity keys"), 500))
                                        }
                                    } else {
                                        Err(util::Error::DefaultWithCode(format!("Error setting the external funding private key"), 500))
                                    }
                                },
                                _ => Err(util::Error::DefaultWithCode(format!("Invitation format is not valid"), 400))
                            },
                        _ => Err(util::Error::DefaultWithCode(format!("Invitation transaction is not valid"), 400))
                    }
                }
            }
        }
    }

    pub async fn create_invitation_full_link_from_identity(&self, identity: &Identity) -> Result<String, util::Error> {
        if let Some(tx) = self.identity.registration_credit_funding_transaction {
            if let Some(instant_lock) = tx.base.instant_send_lock_awaiting_processing {
                DispatchContext::new(DispatchContextType::Global).queue(|| {
                    let sender_username = &identity.current_dashpay_username;
                    let sender_display_name = &identity.display_name;
                    let sender_avatar_path = &identity.avatar_path;
                    let funding_transaction_hex_string = tx.tx_hash().clone().reversed().0.to_hex();
                    let mut registration_funding_private_key = self.identity.internal_registration_funding_private_key.clone();
                    let mut is_cancelled = false;
                    if registration_funding_private_key.is_none() {
                        DispatchContext::main_context().async_queue(||
                           async { match self.chain.authentication_manager.seed_with_prompt("Would you like to share this invitation?".to_string(), self.wallet, 0, false).await {
                                Ok((seed, cancelled)) => {
                                    is_cancelled = cancelled;
                                    if let Some(seed) = seed {
                                        DispatchContext::new(DispatchContextType::Global).queue(|| {
                                            registration_funding_private_key = self.chain.identity_invitation_funding_derivation_path_for_wallet(self.wallet)
                                                .private_key_at_index_path_from_seed(&IndexPath::index_path_with_index(self.identity.index), &seed);
                                        });
                                    }
                                },
                                Err(err) => {  }
                            }
                           }
                        );
                    }
                    if let Some(key) = registration_funding_private_key {
                        // in WIF format
                        let private_key_string = key.serialized_private_key_for_chain(self.chain.script());
                        let serialized_is_lock = instant_lock.to_data().to_hex();
                        match Url::parse("https://invitations.dashpay.io/applink") {
                            Ok(mut url) => {
                                url.query_pairs_mut()
                                    .append_pair("du", sender_username)
                                    .append_pair("assetlocktx", funding_transaction_hex_string.to_lowercase().as_str())
                                    .append_pair("pk", private_key_string.as_str())
                                    .append_pair("islock", serialized_is_lock.as_str());
                                if let Some(display_name) = sender_display_name {
                                    url.query_pairs_mut().append_pair("display-name", display_name);
                                }
                                if let Some(avatar_path) = sender_avatar_path {
                                    url.query_pairs_mut().append_pair("avatar-url", avatar_path);
                                }
                                DispatchContext::main_context().queue(|| Ok(url.as_str().to_string()))
                            },
                            Err(err) => Err(util::Error::Default(err.to_string()))
                        }
                    } else {
                        DispatchContext::main_context().queue(|| Err(util::Error::Default(format!("Can't get registration fundung private key"))))
                    }
                })
            } else {
                Err(util::Error::Default(format!("No instant_send_lock_awaiting_processing for tx")))
            }
        } else {
            Err(util::Error::Default(format!("No registration_credit_funding_transaction")))
        }

    }
}

/// Saving
impl Invitation {
    pub fn save_in_context(&self, context: &ManagedContext) {
        if self.is_transient {
            return;
        }
        context.perform_block_and_wait(|context| {
            let mut change_occured = false;
            let mut update_events = Vec::<&str>::new();
            match self.invitation_entity_in_context(context) {
                Ok(mut entity) => {
                    let mut updates = ();
                    if entity.tag != self.tag {
                        updates.append(invitations::tag.eq(self.tag.clone()));
                        change_occured = true;
                        update_events.push(DSBlockchainInvitationUpdateEvents);
                    }
                    if entity.name != self.name {
                        updates.append(invitations::name.eq(self.name.clone()));
                        change_occured = true;
                        update_events.push(DSBlockchainInvitationUpdateEvents);
                    }
                    if entity.link != self.link {
                        updates.append(invitations::link.eq(self.link.clone()));
                        change_occured = true;
                        update_events.push(DSBlockchainInvitationUpdateEventLink);
                    }
                    if change_occured {
                        //userInfo:@{DSChainManagerNotificationChainKey: self.chain, DSBlockchainInvitationKey: self, DSBlockchainInvitationUpdateEvents: updateEvents}];
                        match entity.update_with(updates, context) {
                            Ok(1) => DispatchContext::main_context().queue(||
                                NotificationCenter::post(Notification::InvitationDidUpdate(self.chain, self/*, update_Events*/))),
                            _ => {}
                        }
                    }
                },
                _ => {}
            }
        });
    }

    /// Deletion
    pub fn delete_persistent_object_and_save(&self, save: bool, context: &ManagedContext) {
        // todo: check with real impl
        context.perform_block_and_wait(|context| {
            match self.invitation_entity_in_context(context) {
                Ok(entity) => InvitationEntity::delete_by_id(entity.id, context),
                Err(err) => Err(err)
            }.expect("can't delete invitation");
            DispatchContext::main_context().queue(||
                NotificationCenter::post(Notification::InvitationDidUpdate(self.chain, self)))
        });
    }

    /// Entity
    pub fn invitation_entity(&self) -> QueryResult<InvitationEntity> {
        self.invitation_entity_in_context(self.chain.view_context())
    }
    pub fn invitation_entity_in_context(&self, context: &ManagedContext) -> QueryResult<InvitationEntity> {
        InvitationEntity::get_by_identity_unique_id(&self.identity.unique_id, context)
    }

}
