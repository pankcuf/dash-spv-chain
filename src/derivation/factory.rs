use std::collections::HashMap;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::credit_funding_derivation_path::CreditFundingDerivationPath;
use crate::derivation::derivation_path::{DerivationPath, IDerivationPath};
use crate::derivation::masternode_holdings_derivation_path::MasternodeHoldingsDerivationPath;
use crate::chain::wallet::wallet::Wallet;
use crate::derivation::uint256_index_path::IIndexPath;

#[derive(Debug, Default)]
pub struct Factory {
    voting_keys_derivation_path_by_wallet: HashMap<String, AuthenticationKeysDerivationPath>,
    owner_keys_derivation_path_by_wallet: HashMap<String, AuthenticationKeysDerivationPath>,
    operator_keys_derivation_path_by_wallet: HashMap<String, AuthenticationKeysDerivationPath>,

    provider_funds_derivation_path_by_wallet: HashMap<String, MasternodeHoldingsDerivationPath>,

    identity_registration_funding_derivation_path_by_wallet: HashMap<String, CreditFundingDerivationPath>,
    identity_topup_funding_derivation_path_by_wallet: HashMap<String, CreditFundingDerivationPath>,
    identity_invitation_funding_derivation_path_by_wallet: HashMap<String, CreditFundingDerivationPath>,
    identity_bls_derivation_path_by_wallet: HashMap<String, AuthenticationKeysDerivationPath>,
    identity_ecdsa_derivation_path_by_wallet: HashMap<String, AuthenticationKeysDerivationPath>,
}

impl Factory {

    pub fn provider_voting_keys_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &AuthenticationKeysDerivationPath {
        self.voting_keys_derivation_path_by_wallet.get(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = AuthenticationKeysDerivationPath::provider_voting_keys_derivation_path_for_wallet(wallet);
            if path.has_extended_public_key() {
                path.load_addresses();
            }
            self.voting_keys_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &path
        })
    }

    pub fn provider_owner_keys_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &AuthenticationKeysDerivationPath {
        self.owner_keys_derivation_path_by_wallet.get(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = AuthenticationKeysDerivationPath::provider_owner_keys_derivation_path_for_wallet(wallet);
            if path.has_extended_public_key() {
                path.load_addresses();
            }
            self.owner_keys_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &path
        })
    }

    pub fn provider_operator_keys_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &AuthenticationKeysDerivationPath {
        self.operator_keys_derivation_path_by_wallet.get(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = AuthenticationKeysDerivationPath::provider_operator_keys_derivation_path_for_wallet(wallet);
            if path.has_extended_public_key() {
                path.load_addresses();
            }
            self.operator_keys_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &path
        })
    }

    pub fn provider_funds_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &MasternodeHoldingsDerivationPath {
        self.provider_funds_derivation_path_by_wallet.get(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = MasternodeHoldingsDerivationPath::provider_funds_derivation_path_for_wallet(wallet);
            if path.has_extended_public_key() {
                path.load_addresses();
            }
            self.provider_funds_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &path
        })
    }

    pub fn identity_registration_funding_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &mut CreditFundingDerivationPath {
        self.identity_registration_funding_derivation_path_by_wallet.get_mut(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = CreditFundingDerivationPath::identity_registration_funding_derivation_path_for_wallet(&wallet);
            if path.has_extended_public_key() {
                path.load_addresses();
            }
            self.identity_registration_funding_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &mut path
        })
    }

    pub fn identity_topup_funding_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &mut CreditFundingDerivationPath {
        self.identity_topup_funding_derivation_path_by_wallet.get_mut(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = CreditFundingDerivationPath::identity_topup_funding_derivation_path_for_wallet(&wallet);
            if path.has_extended_public_key() {
                path.load_addresses();
            }
            self.identity_topup_funding_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &mut path
        })
    }

    pub fn identity_invitation_funding_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &mut CreditFundingDerivationPath {
        self.identity_invitation_funding_derivation_path_by_wallet.get_mut(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = CreditFundingDerivationPath::identity_invitation_funding_derivation_path_for_wallet(&wallet);
            if path.has_extended_public_key() {
                path.load_addresses();
            }
            self.identity_invitation_funding_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &mut path
        })
    }

    /// Identity Authentication
    pub fn identity_bls_keys_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &mut AuthenticationKeysDerivationPath {
        self.identity_bls_derivation_path_by_wallet.get_mut(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = AuthenticationKeysDerivationPath::identity_bls_keys_derivation_path_for_wallet(wallet);
            if path.has_extended_public_key() || (path.has_extended_public_key() && !path.uses_hardened_keys) {
                path.load_addresses();
            }
            self.identity_bls_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &mut path
        })
    }

    pub fn identity_ecdsa_keys_derivation_path_for_wallet(&mut self, wallet: &Wallet) -> &mut AuthenticationKeysDerivationPath {
        self.identity_ecdsa_derivation_path_by_wallet.get_mut(&wallet.unique_id_string).unwrap_or_else(|| {
            let mut path = AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_wallet(wallet);
            if path.has_extended_public_key() || (path.has_extended_public_key() && !path.uses_hardened_keys) {
                path.load_addresses();
            }
            self.identity_ecdsa_derivation_path_by_wallet.insert(wallet.unique_id_string.clone(), path);
            &mut path
        })
    }

    pub fn loaded_specialized_derivation_paths_for_wallet(&mut self, wallet: &Wallet) -> Vec<&dyn IDerivationPath> {
        let mut arr: Vec<&dyn IDerivationPath> = vec![
            self.provider_owner_keys_derivation_path_for_wallet(wallet),
            self.provider_operator_keys_derivation_path_for_wallet(wallet),
            self.provider_voting_keys_derivation_path_for_wallet(wallet),
            self.provider_funds_derivation_path_for_wallet(wallet),
        ];
        if wallet.chain.is_evolution_enabled() {
            arr.push(self.identity_ecdsa_keys_derivation_path_for_wallet(wallet));
            arr.push(self.identity_bls_keys_derivation_path_for_wallet(wallet));
            arr.push(self.identity_registration_funding_derivation_path_for_wallet(wallet));
            arr.push(self.identity_topup_funding_derivation_path_for_wallet(wallet));
        }
        arr
    }

    pub fn fund_derivation_paths_needing_extended_public_key_for_wallet(&self, wallet: &Wallet) -> Vec<Box<dyn IDerivationPath>> {
        let mut arr = Vec::<Box<dyn IDerivationPath>>::new();
        wallet.accounts.values().for_each(|account| {
            account.outgoing_fund_derivation_paths().iter().for_each(|&path| {
                // We should only add derivation paths that are local (ie where we can rederivate)
                // The ones that come from the network should be refetched.
                if !path.base.is_empty() && !path.has_extended_public_key() {
                    arr.push(Box::new(path));
                }
            });
            account.fund_derivation_paths.iter().for_each(|path| {
                arr.push(Box::new(path));
            });
        });
        arr
    }

    pub fn specialized_derivation_paths_needing_extended_public_key_for_wallet(&self, wallet: &Wallet) -> Vec<Box<dyn IDerivationPath>> {
        let mut arr = Vec::<Box<dyn IDerivationPath>>::new();
        self.unloaded_specialized_derivation_paths_for_wallet(wallet).iter().for_each(|&path| {
            if path.has_extended_public_key() {
                arr.push(path);
            }
        });
        if wallet.chain.is_evolution_enabled() {
            wallet.accounts.values().for_each(|account| {
                let mut path = DerivationPath::master_blockchain_identity_contacts_derivation_path_for_account_number(account.account_number, wallet.chain);
                path.wallet = Some(wallet);
                if path.has_extended_public_key() {
                    arr.push(Box::new(path));
                }
            });
        }
        arr
    }

    pub fn unloaded_specialized_derivation_paths_for_wallet(&self, wallet: &Wallet) -> Vec<Box<dyn IDerivationPath>> {
        let mut arr: Vec<Box<dyn IDerivationPath>> = vec![
            // Masternode Owner
            Box::new(AuthenticationKeysDerivationPath::provider_owner_keys_derivation_path_for_wallet(wallet)),
            Box::new(AuthenticationKeysDerivationPath::provider_owner_keys_derivation_path_for_wallet(wallet)),
            // Masternode Operator
            Box::new(AuthenticationKeysDerivationPath::provider_operator_keys_derivation_path_for_wallet(wallet)),
            // Masternode Voting
            Box::new(AuthenticationKeysDerivationPath::provider_voting_keys_derivation_path_for_wallet(wallet)),
            // Masternode Holding
            Box::new(MasternodeHoldingsDerivationPath::provider_funds_derivation_path_for_wallet(wallet)),
        ];
        if wallet.chain.is_evolution_enabled() {
            // Identities
            arr.push(Box::new(AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_wallet(wallet)));
            arr.push(Box::new(AuthenticationKeysDerivationPath::identity_bls_keys_derivation_path_for_wallet(wallet)));
            arr.push(Box::new(CreditFundingDerivationPath::identity_registration_funding_derivation_path_for_wallet(wallet)));
            arr.push(Box::new(CreditFundingDerivationPath::identity_topup_funding_derivation_path_for_wallet(wallet)));
            arr.push(Box::new(CreditFundingDerivationPath::identity_invitation_funding_derivation_path_for_wallet(wallet)));
        }
        arr
    }

}
