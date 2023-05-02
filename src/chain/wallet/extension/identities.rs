use std::collections::{HashMap, HashSet};
use hashes::Hash;
use crate::chain::ext::derivation::Derivation;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::byte_util::{AsBytes, Reversable, Zeroable};
use crate::crypto::UInt256;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::simple_indexed_derivation_path::ISimpleIndexedDerivationPath;
use crate::keychain::extension::identity::{IDENTITY_INDEX_KEY, IDENTITY_LOCKED_OUTPUT_KEY};
use crate::keychain::IdentityKeychainDTO;
use crate::keychain::keychain::Keychain;
use crate::platform::contract::contract::Contract;
use crate::platform::identity::identity::Identity;
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::tx::special::credit_funding_transaction::CreditFundingTransactionEntity;

/// Wallet operations with identities
pub trait WalletIdentities {
    fn identity_addresses(&self) -> HashSet<String>;
    fn unregister_identity(&mut self, identity: &Identity);
    fn add_identities(&mut self, identities: Vec<Identity>);
    fn add_identity(&mut self, identity: &Identity);
    fn contains_identity(&self, identity: &Identity) -> bool;
    fn register_identities(&mut self, identities: Vec<&mut Identity>, verify: bool) -> bool;
    fn register_identity(&mut self, identity: &mut Identity) -> bool;
    fn register_identity_and_verify(&mut self, identity: &mut Identity, verify: bool) -> bool;
    fn identity_that_created_contract(&self, contract: &mut Contract, contract_id: &UInt256) -> Option<&Identity>;
    fn identity_for_unique_id(&self, unique_id: UInt256) -> Option<&Identity>;
    fn identities_count(&self) -> u32;
    fn upgrade_identity_key_chain(&self) -> bool;
    fn identities(&mut self) -> &HashMap<UInt256, &Identity>;
    // fn identities(&mut self) -> Option<&HashMap<UInt256, &Identity>>;
    fn set_default_identity(&mut self, identity: Identity);
    fn unused_identity_index(&self) -> u32;
    fn create_identity(&self) -> Identity;
    fn create_identity_using_derivation_index(&self, index: u32) -> Identity;
    fn create_identity_for_username(&self, username: String) -> Identity;
    fn create_identity_for_username_using_derivation_index(&self, username: String, index: u32) -> Identity;
}

impl WalletIdentities for Wallet {

    /// Blockchain Identities

    fn identity_addresses(&self) -> HashSet<String> {
        let mut path = self.chain.identity_bls_keys_derivation_path_for_wallet(self);
        if path.has_extended_public_key() {
            path.addresses_to_index_using_cache(self.unused_identity_index() + 10, true, true)
        } else {
            HashSet::new()
        }
    }

    fn unregister_identity(&mut self, identity: &Identity) {
        assert_eq!(identity.wallet, Some(self), "the blockchainIdentity you are trying to remove is not in this wallet");
        self.identities.remove(&identity.unique_id);
        Keychain::set_dict(Keychain::get_dict(self.wallet_identities_key()).map_or(HashMap::new(), |mut dict| {
            dict.remove(&identity.unique_id);
            dict
        }), self.wallet_identities_key(), false).expect("Can't store changes in identities");
    }

    fn add_identities(&mut self, identities: Vec<Identity>) {
        identities.iter().for_each(|&identity| self.add_identity(&identity));
    }

    fn add_identity(&mut self, identity: &Identity) {
        assert!(!identity.unique_id.is_zero(), "The blockchain identity unique ID must be set");
        self.identities.insert(identity.unique_id, identity);
    }

    fn contains_identity(&self, identity: &Identity) -> bool {
        if let Some(outpoint) = identity.locked_outpoint {
            self.identities.contains_key(&identity.unique_id)
        } else {
            false
        }
    }

    fn register_identities(&mut self, identities: Vec<&mut Identity>, verify: bool) -> bool {
        self.identities.values_mut().find(|&identity| !self.register_identity_and_verify(identity, verify)).is_some()
    }

    fn register_identity(&mut self, mut identity: &mut Identity) -> bool {
        self.register_identity_and_verify(identity, false)
    }

    fn register_identity_and_verify(&mut self, mut identity: &mut Identity, verify: bool) -> bool {
        if verify {
            let verified = (&mut identity).verify_keys_for_wallet(self);
            if !verified {
                identity.is_local = false;
                return false;
            }
        }
        if !self.identities.contains_key(&identity.unique_id) {
            self.add_identity(identity)
        }
        match Keychain::get_dict(self.wallet_identities_key()) {
            Ok(mut keyChainDictionary) => {
                assert!(!identity.unique_id.is_zero(), "registrationTransactionHashData must not be null");
                if identity.locked_outpoint.unwrap().hash.is_zero() {
                    keyChainDictionary.insert(
                        identity.unique_id.clone(),
                        HashMap::from([
                            (IDENTITY_INDEX_KEY.to_string(), identity.index.clone())
                        ]));
                } else {
                    keyChainDictionary.insert(
                        identity.unique_id.clone(),
                        HashMap::from([
                            (IDENTITY_INDEX_KEY.to_string(), identity.index.clone()),
                            (IDENTITY_LOCKED_OUTPUT_KEY.to_string(), identity.locked_outpoint.unwrap().clone())
                        ]));
                }
                Keychain::set_dict(keyChainDictionary, self.wallet_identities_key(), false)
                    .expect("Can't store updates for key_chain_dictionary");
                if self.default_identity.is_none() && identity.index == 0 {
                    self.default_identity = Some(&identity);
                }
                true
            },
            Err(err) => false
        }
    }

    fn identity_that_created_contract(&self, contract: &mut Contract, contract_id: &UInt256) -> Option<&Identity> {
        assert!(!contract_id.is_zero(), "contract_id must not be null");
        self.identities.values().find(|&&identity| contract.contract_id_if_registered_by_identity(identity) == *contract_id).map(|&i| i)
    }

    fn identity_for_unique_id(&self, unique_id: UInt256) -> Option<&Identity> {
        assert!(!unique_id.is_zero(), "unique_id must not be null");
        self.identities.values().find(|&&identity| identity.unique_id == unique_id).map(|&i| i)
    }

    fn identities_count(&self) -> u32 {
        self.identities.len() as u32
    }

    fn upgrade_identity_key_chain(&self) -> bool {
        match Keychain::get_dict::<UInt256, IdentityKeychainDTO>(self.wallet_identities_key()) {
            Ok(mut dict) => {
                dict.into_iter().for_each(|(unique_id, IdentityKeychainDTO { index, locked_outpoint, ..})| {
                    dict.insert(UInt256::sha256d(unique_id.as_bytes()), IdentityKeychainDTO { index, locked_outpoint });
                });
                match Keychain::set_dict(dict, self.wallet_identities_key(), false) {
                    Ok(..) => true,
                    Err(err) => false
                }
            }
            Err(err) => {
                assert!(false, "There should be no error during upgrade");
                false
            }
        }
    }

    // This loads all the identities that the wallet knows about.
    // If the app was deleted and reinstalled the identity information will remain from the
    // keychain but must be reaquired from the network.
    fn identities(&mut self) -> &HashMap<UInt256, &Identity> {
        if self.identities_loaded {
            return &self.identities;
        }
        let mut identities = HashMap::<UInt256, &Identity>::new();
        match Keychain::get_dict::<UInt256, IdentityKeychainDTO>(self.wallet_identities_key()) {
            Ok(mut dict) => {
                let default_index = match Keychain::get_int(self.wallet_identities_default_index_key()) {
                    Ok(default_index) => default_index as u64,
                    Err(err) => panic!("Can't read wallet_blockchain_identities_default_index_key from Keychain")
                };
                if !dict.is_empty() {
                    // if ([[[keyChainDictionary allValues] firstObject] isKindOfClass:[NSNumber class]]) {
                    // todo: check this
                    if false {
                        return if self.upgrade_identity_key_chain() {
                            self.identities()
                        } else {
                            None
                        }
                    }
                    dict.iter().for_each(|(unique_id_data, object)| {
                        let index = object.index;
                        let context = self.chain.chain_context(); // shouldn't matter what context is used
                        let locked_outpoint = &object.locked_outpoint;
                        let identity = match IdentityEntity::count_local_identities_for_chain_type(self.chain.r#type(), context) {
                            Ok(blockchainIdentityEntitiesCount) => {
                                if blockchainIdentityEntitiesCount as usize != dict.len() {
                                    println!("Unmatching blockchain entities count");
                                }
                                IdentityEntity::identity_with_unique_id(unique_id_data, context)
                                    .map(|identity_entity|
                                        locked_outpoint.map_or(
                                            Identity::init_at_with_unique_id(index, unique_id_data.clone(), self),
                                            |o| Identity::init_at_with_locked_outpoint_and_entity(index, &o, self, &identity_entity)))
                            },
                            Err(err) => {
                                let identity = match locked_outpoint {
                                    Some(locked_outpoint) => {
                                        // No blockchain identity is known in core data
                                        let transaction_hash = locked_outpoint.hash.clone().reversed();
                                        match CreditFundingTransactionEntity::get_by_tx_hash(&locked_outpoint.hash, context) {
                                            Ok((credit_regitration_transaction_entity, base_entity)) => {
                                                // The registration funding transaction exists
                                                // Weird but we should recover in this situation
                                                let registration_transaction = CreditFundingTransaction::from_entity((credit_regitration_transaction_entity, base_entity), context);
                                                let registration_funding_derivation_path = self.chain.identity_registration_funding_derivation_path_for_wallet(self);
                                                let correct_index = registration_transaction.check_derivation_path_index_for_wallet(&registration_funding_derivation_path, index);
                                                if !correct_index {
                                                    assert!(false, "We should implement this");
                                                    None
                                                } else {
                                                    let mut identity = Identity::init_at_with_credit_funding_transaction_and_username_dictionary(index, &registration_transaction, None, self);
                                                    identity.register_in_wallet();
                                                    identity
                                                }
                                            },
                                            Err(..) => {
                                                // We also don't have the registration funding transaction
                                                let mut identity = Identity::init_at_with_unique_id(index, unique_id_data.clone(), self);
                                                identity.register_in_wallet_for_blockchain_identity_unique_id(unique_id_data.clone());
                                                Some(identity)
                                            }
                                        }
                                    },
                                    None => {
                                        // We also don't have the registration funding transaction
                                        let mut identity = Identity::init_at_with_unique_id(index, unique_id_data.clone(), self);
                                        identity.register_in_wallet_for_blockchain_identity_unique_id(unique_id_data.clone());
                                        Some(identity);
                                    }
                                };
                            }
                        };
                        if let Some(identity) = identity {
                            identities.insert(unique_id_data.clone(), identity);
                            if index as u64 == default_index {
                                self.default_identity = Some(&identity);
                            }
                        }
                    });
                }
            }
            Err(err) => {}
        }
        self.identities = identities;
        &identities
    }

    fn set_default_identity(&mut self, identity: Identity) {
        if self.identities.values().find(|i| i == identity).is_some() {
            return;
        }
        self.default_identity = Some(&identity);
        Keychain::set_int(identity.index as i64, self.wallet_identities_default_index_key(), false)
            .expect("Can't store default identity index");
    }

    fn unused_identity_index(&self) -> u32 {
        if let Some(max) = self.identities.values().map(|identity| identity.index).max() {
            max + 1
        } else {
            0
        }
    }

    fn create_identity(&self) -> Identity {
        Identity::init_at(self.unused_identity_index(), self)
    }

    fn create_identity_using_derivation_index(&self, index: u32) -> Identity {
        Identity::init_at(index, self)
    }

    fn create_identity_for_username(&self, username: String) -> Identity {
        let mut s = self.create_identity();
        s.add_dashpay_username(username, false);
        s
    }

    fn create_identity_for_username_using_derivation_index(&self, username: String, index: u32) -> Identity {
        let mut s = self.create_identity_using_derivation_index(index);
        s.add_dashpay_username(username, false);
        s
    }
}
