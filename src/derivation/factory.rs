use std::collections::HashMap;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::credit_funding_derivation_path::CreditFundingDerivationPath;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::masternode_holdings_derivation_path::MasternodeHoldingsDerivationPath;
use crate::chain::wallet::wallet::Wallet;

pub struct Factory {

    votingKeysDerivationPathByWallet: HashMap<>
    ownerKeysDerivationPathByWallet;
    operatorKeysDerivationPathByWallet;
    providerFundsDerivationPathByWallet;
    blockchainIdentityRegistrationFundingDerivationPathByWallet;
    blockchainIdentityTopupFundingDerivationPathByWallet;
    blockchainIdentityInvitationFundingDerivationPathByWallet;
    blockchainIdentityBLSDerivationPathByWallet;
    blockchainIdentityECDSADerivationPathByWallet;

}

impl Factory {

    pub fn provider_voting_keys_derivation_path_for_wallet(&self, wallet: &Wallet) -> AuthenticationKeysDerivationPath {
        todo!()
    }

    pub fn provider_owner_keys_derivation_path_for_wallet(&self, wallet: &Wallet) -> AuthenticationKeysDerivationPath {
        todo!()
    }

    pub fn provider_operator_keys_derivation_path_for_wallet(&self, wallet: &Wallet) -> AuthenticationKeysDerivationPath {
        todo!()
    }

    pub fn provider_funds_derivation_path_for_wallet(&self, wallet: &Wallet) -> MasternodeHoldingsDerivationPath {
        todo!()
    }

    pub fn blockchain_identity_registration_funding_derivation_path_for_wallet(&self, wallet: &Wallet) -> CreditFundingDerivationPath {
        todo!()
    }

    pub fn blockchain_identity_topup_funding_derivation_path_for_wallet(&self, wallet: &Wallet) -> CreditFundingDerivationPath {
        todo!()
    }

    pub fn blockchain_identity_invitation_funding_derivation_path_for_wallet(&self, wallet: &Wallet) -> CreditFundingDerivationPath {
        todo!()
    }

    /// Blockchain Identity Authentication
    pub fn blockchain_identity_bls_keys_derivation_path_for_wallet(&self, wallet: &Wallet) -> AuthenticationKeysDerivationPath {
        todo!()
    }

    pub fn blockchain_identity_ecdsa_keys_derivation_path_for_wallet(&self, wallet: &Wallet) -> AuthenticationKeysDerivationPath {
        todo!()
    }

    pub fn loaded_specialized_derivation_paths_for_wallet(&self, wallet: &Wallet) -> Vec<dyn IDerivationPath> {
        let mut arr = vec![
            Self::provider_owner_keys_derivation_path_for_wallet(wallet)
        ];

        NSMutableArray *mArray = [NSMutableArray array];
        [mArray addObject:[[DSDerivationPathFactory sharedInstance] providerOwnerKeysDerivationPathForWallet:wallet]];
        [mArray addObject:[[DSDerivationPathFactory sharedInstance] providerOperatorKeysDerivationPathForWallet:wallet]];
        [mArray addObject:[[DSDerivationPathFactory sharedInstance] providerVotingKeysDerivationPathForWallet:wallet]];
        [mArray addObject:[[DSDerivationPathFactory sharedInstance] providerFundsDerivationPathForWallet:wallet]];
        if (wallet.chain.isEvolutionEnabled) {
            [mArray addObject:[[DSDerivationPathFactory sharedInstance] blockchainIdentityECDSAKeysDerivationPathForWallet:wallet]];
            [mArray addObject:[[DSDerivationPathFactory sharedInstance] blockchainIdentityBLSKeysDerivationPathForWallet:wallet]];
            [mArray addObject:[[DSDerivationPathFactory sharedInstance] blockchainIdentityRegistrationFundingDerivationPathForWallet:wallet]];
            [mArray addObject:[[DSDerivationPathFactory sharedInstance] blockchainIdentityTopupFundingDerivationPathForWallet:wallet]];
        }
        return mArray;
    }

    pub fn fund_derivation_paths_needing_extended_public_key_for_wallet(&self, wallet: &Wallet) -> Vec<dyn IDerivationPath> {
        todo!()
    }

    pub fn specialized_derivation_paths_needing_extended_public_key_for_wallet(&self, wallet: &Wallet) -> Vec<dyn IDerivationPath> {
        todo!()
    }

    pub fn unloaded_specialized_derivation_paths_for_wallet(&self, wallet: &Wallet) -> Vec<dyn IDerivationPath> {
        todo!()
    }

}
