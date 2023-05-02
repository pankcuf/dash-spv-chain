use crate::chain::chain::Chain;
use crate::chain::wallet::wallet::Wallet;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::credit_funding_derivation_path::CreditFundingDerivationPath;
use crate::derivation::derivation_path::{DerivationPath, IDerivationPath};
use crate::derivation::factory::Factory;
use crate::derivation::funds_derivation_path::FundsDerivationPath;
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;

pub trait Derivation {
    fn factory(&self) -> &Factory;
    fn identity_registration_funding_derivation_path_for_wallet(&self, wallet: &Wallet) -> &mut CreditFundingDerivationPath {
        self.factory().identity_registration_funding_derivation_path_for_wallet(wallet)
    }
    fn identity_topup_funding_derivation_path_for_wallet(&self, wallet: &Wallet) -> &mut CreditFundingDerivationPath {
        self.factory().identity_topup_funding_derivation_path_for_wallet(wallet)
    }

    fn identity_invitation_funding_derivation_path_for_wallet(&self, wallet: &Wallet) -> &mut CreditFundingDerivationPath {
        self.factory().identity_invitation_funding_derivation_path_for_wallet(wallet)
    }

    fn identity_ecdsa_keys_derivation_path_for_wallet(&self, wallet: &Wallet) -> &mut AuthenticationKeysDerivationPath {
        self.factory().identity_ecdsa_keys_derivation_path_for_wallet(wallet)
    }
    fn identity_bls_keys_derivation_path_for_wallet(&self, wallet: &Wallet) -> &mut AuthenticationKeysDerivationPath {
        self.factory().identity_bls_keys_derivation_path_for_wallet(wallet)
    }

    fn standard_derivation_paths_for_account_number(&self, account_number: u32) -> Vec<Box<dyn IDerivationPath>>;
    fn identity_funding_private_key_for_wallet(&self, wallet: &Wallet, is_for_invitation: bool, index: u32, seed: &Vec<u8>) -> Option<ECDSAKey>;


    fn identity_ecdsa_keys_extended_public_key_for_wallet_from_seed(&self, wallet: &Wallet, seed: &Vec<u8>) -> Option<&dyn IKey> {
        self.factory().identity_ecdsa_keys_derivation_path_for_wallet(wallet)
            .generate_extended_public_key_from_seed(seed, Some(&wallet.unique_id_string))
    }
    fn identity_bls_keys_extended_public_key_for_wallet_from_seed(&self, wallet: &Wallet, seed: &Vec<u8>) -> Option<&dyn IKey> {
        self.factory().identity_bls_keys_derivation_path_for_wallet(wallet)
            .generate_extended_public_key_from_seed(seed, Some(&wallet.unique_id_string))
    }

    fn identity_registration_funding_extended_public_key_for_wallet_from_seed(&self, wallet: &Wallet, seed: &Vec<u8>) -> Option<&dyn IKey> {
        self.factory().identity_registration_funding_derivation_path_for_wallet(wallet)
            .generate_extended_public_key_from_seed(seed, Some(&wallet.unique_id_string))
    }

    fn identity_topup_funding_extended_public_key_for_wallet_from_seed(&self, wallet: &Wallet, seed: &Vec<u8>) -> Option<&dyn IKey> {
        self.factory().identity_topup_funding_derivation_path_for_wallet(wallet)
            .generate_extended_public_key_from_seed(seed, Some(&wallet.unique_id_string))
    }

    fn identity_invitation_funding_extended_public_key_for_wallet_from_seed(&self, wallet: &Wallet, seed: &Vec<u8>) -> Option<&dyn IKey> {
        self.factory().identity_invitation_funding_derivation_path_for_wallet(wallet)
            .generate_extended_public_key_from_seed(seed, Some(&wallet.unique_id_string))
    }
}

impl Derivation for Chain {
    fn factory(&self) -> &Factory {
        &self.derivation_path_factory
    }
    fn standard_derivation_paths_for_account_number(&self, account_number: u32) -> Vec<Box<dyn IDerivationPath>> {
        if account_number == 0 {
            vec![
                Box::new(FundsDerivationPath::bip32_derivation_path_for_account_number(account_number, self)),
                Box::new(FundsDerivationPath::bip44_derivation_path_for_account_number(account_number, self)),
                Box::new(DerivationPath::master_blockchain_identity_contacts_derivation_path_for_account_number(account_number, self))
            ]
        } else {
            // don't include BIP32 derivation path on higher accounts
            vec![
                Box::new(FundsDerivationPath::bip44_derivation_path_for_account_number(account_number, self)),
                Box::new(DerivationPath::master_blockchain_identity_contacts_derivation_path_for_account_number(account_number, self))
            ]
        }
    }

    fn identity_funding_private_key_for_wallet(&self, wallet: &Wallet, is_for_invitation: bool, index: u32, seed: &Vec<u8>) -> Option<ECDSAKey> {
        if is_for_invitation {
            self.identity_invitation_funding_derivation_path_for_wallet(wallet)
                .private_key_at_index_path_from_seed(&IndexPath::index_path_with_index(index), seed)
        } else {
            self.identity_registration_funding_derivation_path_for_wallet(wallet)
                .private_key_at_index_path_from_seed(&IndexPath::index_path_with_index(index), seed)
        }
    }
}
