use bip39::Language;
use hashes::{Hash, sha256};
use crate::chain::chain::Chain;
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::wallet::Wallet;
use crate::consensus::Encodable;
use crate::crypto::UInt512;
use crate::util::data_ops::short_hex_string_from;
use crate::derivation::derivation_path::IDerivationPath;
use crate::keychain::keychain::Keychain;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::manager::authentication_manager::AuthenticationError;
use crate::util;

pub const SEED_ENTROPY_LENGTH: usize = 128 / 8;

pub type SeedCompletionBlock = fn(seed: Option<Vec<u8>>, cancelled: bool);
pub type SeedRequestBlock = fn(authprompt: Option<String>, amount: u64, seed_completion: SeedCompletionBlock);

pub trait Seed {
    fn generate_random_seed_phrase_for_language(language: Language) -> Option<bip39::Mnemonic>;
    fn generate_random_seed_phrase() -> Option<bip39::Mnemonic>;
    fn seed_phrase_after_authentication(&self) -> Result<String, AuthenticationError>;
    fn has_seed_phrase(&self) -> bool;
    fn set_transient_derived_key_data(derived_key_data: &Vec<u8>, accounts: &Vec<Account>, chain: &Chain) -> String;
    fn set_seed_phrase(seed_phrase: String, created_at: u64, accounts: Vec<Account>, store_on_keychain: bool, chain: &Chain) -> Option<String>;
    fn seed_with_prompt(&self, authprompt: Option<String>, amount: u64) -> Result<(Option<Vec<u8>>, bool), util::Error>;
    fn seed_phrase_if_authenticated(&self) -> Option<String>;
    fn seed_phrase_after_authentication_with_prompt(&self, authprompt: Option<String>) -> Result<String, AuthenticationError>;
}

impl Seed for Wallet {
    /// Seed

    // generates a random seed, saves to keychain and returns the associated seed_phrase
    fn generate_random_seed_phrase_for_language(language: Language) -> Option<bip39::Mnemonic> {
        bip39::Mnemonic::generate_in(language, SEED_ENTROPY_LENGTH).ok()
    }


    fn generate_random_seed_phrase() -> Option<bip39::Mnemonic> {
        Self::generate_random_seed_phrase_for_language(Language::English)
    }

    fn seed_phrase_after_authentication(&self) -> Result<String, AuthenticationError> {//, void (^)(NSString *_Nullable))completion {
        self.seed_phrase_after_authentication_with_prompt(None)
    }

    fn has_seed_phrase(&self) -> bool {
        Keychain::has_data(self.unique_id_string.clone()).unwrap_or(false)
    }

    fn set_transient_derived_key_data(derived_key_data: &Vec<u8>, accounts: &Vec<Account>, chain: &Chain) -> String {
        let i = UInt512::bip32_seed_key(derived_key_data);
        let mut unique_id_data = Vec::<u8>::new();
        chain.r#type().genesis_hash().enc(&mut unique_id_data);
        if let Some(mut public_key) = ECDSAKey::key_with_secret(&i.0[..32].to_vec(), true) {
            public_key.public_key_data().enc(&mut unique_id_data);
        }
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
        if let Ok(mnemonic) = bip39::Mnemonic::parse_normalized(seed_phrase.as_str()) {
            let derived_key_data = mnemonic.to_seed_normalized("").to_vec();
            let seed_key = UInt512::bip32_seed_key(&derived_key_data);
            let mut unique_id_data = Vec::<u8>::new();
            chain.r#type().genesis_hash().enc(&mut unique_id_data);
            if let Some(mut public_key) = ECDSAKey::key_with_secret(&seed_key.0[..32].to_vec(), true) {
                public_key.public_key_data().enc(&mut unique_id_data);
            }
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
    fn seed_with_prompt(&self, authprompt: Option<String>, amount: u64) -> Result<(Option<Vec<u8>>, bool), util::Error> {
        if authprompt.is_none() && self.chain.authentication_manager.did_authenticate {
            let phrase = Keychain::get_string(self.mnemonic_unique_id()).expect("Can't retrieve mnemonic");
            // return bip39::Mnemonic::parse_normalized(phrase.as_str())
            //     .map_err(bip39::Error::into)
            //     .map_or(Ok((None, false)), |mnemonic| Ok(Some(mnemonic.to_seed_normalized("").to_vec()), false)));
            return if let Ok(mnemonic) = bip39::Mnemonic::parse_normalized(phrase.as_str()) {
                Ok((Some(mnemonic.to_seed_normalized("").to_vec()), false))
            } else {
                Ok((None, false))
            }
        }
        let using_biometric_authentication = if amount != 0 { self.chain.authentication_manager.can_use_biometric_authentication_for_amount(amount) } else { false };
        match futures::executor::block_on(self.chain.authentication_manager.authenticate_with_prompt(authprompt, using_biometric_authentication, true)) {
            Ok((authenticated, used_biometrics, cancelled)) =>
                if authenticated && (!used_biometrics || self.chain.authentication_manager.update_biometrics_amount_left_after_spending_amount(amount)) {
                    bip39::Mnemonic::parse_normalized(Keychain::get_string(self.mnemonic_unique_id()).expect("Can't retrieve mnemonic").as_str())
                        .map_or(Ok((None, cancelled)), |mnemonic| Ok((Some(mnemonic.to_seed_normalized("").to_vec()), cancelled)))
                } else {
                    Ok((None, cancelled))
                },
            Err(err) => Err(err.into())
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
        match futures::executor::block_on(self.chain.authentication_manager.authenticate_with_prompt(authprompt, false, true)) {
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
