use hashes::{Hash, sha256};
use ring::{hmac, rand};
use crate::chain::chain::Chain;
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::bip39_language::Bip39Language;
use crate::chain::wallet::bip39_mnemonic::BIP39Mnemonic;
use crate::chain::wallet::wallet::Wallet;
use crate::consensus::Encodable;
use crate::crypto::data_ops::short_hex_string_from;
use crate::derivation::derivation_path::IDerivationPath;
use crate::keychain::keychain::Keychain;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::manager::authentication_manager::AuthenticationError;

pub const SEED_ENTROPY_LENGTH: u32 = 128 / 8;

pub type SeedCompletionBlock = fn(seed: Option<Vec<u8>>, cancelled: bool);
pub type SeedRequestBlock = fn(authprompt: Option<String>, amount: u64, seed_completion: Option<SeedCompletionBlock>);

pub trait Seed {
    fn generate_random_seed_phrase_for_language(language: Bip39Language) -> String;
    fn generate_random_seed_phrase() -> String;
    fn seed_phrase_after_authentication(&self) -> Resultg<String, AuthenticationError>;
    fn has_seed_phrase(&self) -> bool;
    fn set_transient_derived_key_data(derived_key_data: &Vec<u8>, accounts: &Vec<Account>, chain: &Chain) -> String;
    fn set_seed_phrase(seed_phrase: String, created_at: u64, accounts: Vec<Account>, store_on_keychain: bool, chain: &Chain) -> Option<String>;
    fn seed_with_prompt(&self, authprompt: Option<String>, amount: u64, completion: SeedCompletionBlock);
    fn seed_phrase_if_authenticated(&self) -> Option<String>;
    fn seed_phrase_after_authentication_with_prompt(&self, authprompt: Option<String>) -> Result<String, AuthenticationError>;
}

impl Seed for Wallet {
    /// Seed

    // generates a random seed, saves to keychain and returns the associated seed_phrase
    fn generate_random_seed_phrase_for_language(language: Bip39Language) -> String {
        //NSMutableData *entropy = [NSMutableData secureDataWithLength:SEED_ENTROPY_LENGTH];
        //if (SecRandomCopyBytes(kSecRandomDefault, entropy.length, entropy.mutableBytes) != 0) return nil;
        // todo: SecureAllocator
        let entropy = Vec::<u8>::with_capacity(SEED_ENTROPY_LENGTH as usize);
        if language != Bip39Language::Default {
            // BIP39Mnemonic
            // [[DSBIP39Mnemonic sharedInstance] setDefaultLanguage:language];
        }
        let phrase = BIP39Mnemonic::encode_phrase(entropy);
        // NSString *phrase = [[DSBIP39Mnemonic sharedInstance] encodePhrase:entropy];
        phrase
    }


    fn generate_random_seed_phrase() -> String {
        Self::generate_random_seed_phrase_for_language(Bip39Language::Default)
    }

    fn seed_phrase_after_authentication(&self) -> Resultg<String, AuthenticationError> {//, void (^)(NSString *_Nullable))completion {
        self.seed_phrase_after_authentication_with_prompt(None)
    }

    fn has_seed_phrase(&self) -> bool {
        Keychain::has_data(self.unique_id_string.clone()).unwrap_or(false)
    }

    fn set_transient_derived_key_data(derived_key_data: &Vec<u8>, accounts: &Vec<Account>, chain: &Chain) -> String {
        todo!("check this HMAC implementation");
        // UInt512 I;
        // HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), derivedKeyData.bytes, derivedKeyData.length);
        // NSData *publicKey = [DSECDSAKey keyWithSecret:*(UInt256 *)&I compressed:YES].publicKeyData;
        let rng = rand::SystemRandom::new();
        let key = hmac::Key::generate(hmac::HMAC_SHA512, &rng)?;
        let tag = hmac::sign(&key, derived_key_data);
        let public_key = ECDSAKey::key_with_secret(&tag.as_ref().to_vec(), true)?.public_key_data();
        let mut unique_id_data = Vec::<u8>::new();
        chain.params.chain_type.genesis_hash().enc(&mut unique_id_data);
        public_key.enc(&mut unique_id_data);
        let unique_id = short_hex_string_from(&sha256::Hash::hash(unique_id_data.as_slice()).into_inner());
        accounts.iter().for_each(|account| {
            account.fund_derivation_paths.iter().for_each(|mut derivation_path| {
                derivation_path.generate_extended_public_key_from_seed(derived_key_data, None);
            });
            if chain.is_evolution_enabled() {
                account.master_contacts_derivation_path.unwrap().generate_extended_public_key_from_seed(derived_key_data, None);
            }
        });
        unique_id
    }



    fn set_seed_phrase(seed_phrase: String, created_at: u64, accounts: Vec<Account>, store_on_keychain: bool, chain: &Chain) -> Option<String> {
        todo!("check this HMAC implementation");
        if let Some(seed_phrase) = BIP39Mnemonic::normalize_phrase(&seed_phrase) {
            // we store the wallet creation time on the keychain because keychain data persists even when an app is deleted
            let derived_key_data = BIP39Mnemonic::derive_key_from_phrase(&seed_phrase, None);
            let rng = rand::SystemRandom::new();
            let key = hmac::Key::generate(hmac::HMAC_SHA512, &rng)?;
            let tag = hmac::sign(&key, &derived_key_data);
            let public_key = ECDSAKey::key_with_secret(&tag.as_ref().to_vec(), true)?.public_key_data();
            let mut unique_id_data = Vec::<u8>::new();
            chain.params.chain_type.genesis_hash().enc(&mut unique_id_data);
            public_key.enc(&mut unique_id_data);
            let unique_id = short_hex_string_from(&sha256::Hash::hash(unique_id_data.as_slice()).into_inner());
            // if not store on keychain then we won't save the extended public keys below.
            let mut store_on_unique_id: Option<&String> = None;
            if store_on_keychain {
                if Keychain::set_string(seed_phrase, Wallet::mnemonic_unique_id_for_unique_id(&unique_id), true).is_err() ||
                    (created_at != 0 && Keychain::set_data(Wallet::creation_time_unique_id_for_unique_id(&unique_id), Some(created_at.to_le_bytes().to_vec()), false).is_err()) {
                    assert!(false, "error setting wallet seed");
                    return None;
                }
                // in version 2.0.0 wallet creation times were migrated from reference date,
                // since this is now fixed just add this line so verification only happens once
                Keychain::set_int(1, Wallet::did_verify_creation_time_unique_id_for_unique_id(&unique_id), false).expect("Can't store VerifyCreationTimeUniqueID");
                store_on_unique_id = Some(&unique_id);
            }
            accounts.iter().for_each(|account| {
                account.fund_derivation_paths.iter().for_each(|mut derivation_path| {
                    derivation_path.generate_extended_public_key_from_seed(&derived_key_data, store_on_unique_id);
                });
                if chain.is_evolution_enabled() {
                    account.master_contacts_derivation_path.unwrap().generate_extended_public_key_from_seed(&derived_key_data, store_on_unique_id);
                }
            });
            Some(unique_id)
        } else {
            None
        }
    }

    // authenticates user and returns seed
    fn seed_with_prompt(&self, authprompt: Option<String>, amount: u64, completion: SeedCompletionBlock) {
        if authprompt.is_none() && self.chain.authentication_manager.did_authenticate {
            let phrase = Keychain::get_string(self.mnemonic_unique_id()).expect("Can't retrieve mnemonic");
            let key = BIP39Mnemonic::derive_key_from_phrase(&phrase, None);
            completion(Some(key), false);
            return;
        }
        let using_biometric_authentication = if amount != 0 { self.chain.authentication_manager.can_use_biometric_authentication_for_amount(amount) } else { false };
        match self.chain.authentication_manager.authenticate_with_prompt(authprompt, using_biometric_authentication, true) {
            Ok((authenticated, used_biometrics, cancelled)) => {
                if !authenticated {
                    completion(None, cancelled);
                } else {
                    if used_biometrics && !self.chain.authentication_manager.update_biometrics_amount_left_after_spending_amount(amount) {
                        completion(None, cancelled);
                    } else {
                        let phrase = Keychain::get_string(self.mnemonic_unique_id()).expect("Can't retrieve mnemonic");
                        let key = BIP39Mnemonic::derive_key_from_phrase(&phrase, None);
                        completion(Some(key), cancelled);
                    }
                }
            },
            Err(err) => Err(err)
        }
    }

    fn seed_phrase_if_authenticated(&self) -> Option<String> {
        if !self.chain.authentication_manager.uses_authentication || self.chain.authentication_manager.did_authenticate {
            Keychain::get_string(self.mnemonic_unique_id()).ok()
        } else {
            None
        }
    }

    /// authenticates user and returns seedPhrase
    fn seed_phrase_after_authentication_with_prompt(&self, authprompt: Option<String>) -> Result<String, AuthenticationError> {
        match self.chain.authentication_manager.authenticate_with_prompt(authprompt, false, true) {
            Ok((true, used_biometrics, cancelled)) => {
                match Keychain::get_string(self.mnemonic_unique_id()) {
                    Ok(seed) => Ok(seed),
                    Err(err) => Err(AuthenticationError::CannotRetrieveSeedFromKeychain)
                }
            },
            _ => Err(AuthenticationError::NotAuthenticated)
        }
    }
}
