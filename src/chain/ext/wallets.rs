use crate::crypto::{UInt160, UInt384};
use crate::chain::tx::transaction::ITransaction;
use crate::chain::chain::Chain;
use crate::chain::tx::provider_registration_transaction::ProviderRegistrationTransaction;
use crate::chain::wallet::extension::masternodes::Masternodes;
use crate::chain::wallet::wallet::Wallet;

pub trait Wallets {
    /// Merging Wallets
    fn wallet_having_identity_credit_funding_registration_hash(&self, credit_funding_registration_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_identity_credit_funding_topup_hash(&self, credit_funding_topup_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_identity_credit_funding_invitation_hash(&self, credit_funding_invitation_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_provider_voting_authentication_hash(&self, voting_authentication_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_provider_owner_authentication_hash(&self, owner_authentication_hash: &UInt160) -> Option<(&Wallet, u32)>;
    fn wallet_having_provider_operator_authentication_key(&self, key: &UInt384) -> Option<(&Wallet, u32)>;
    fn wallet_containing_masternode_holding_address_for_provider_registration_transaction(&self, transaction: &ProviderRegistrationTransaction) -> Option<(&Wallet, u32)>;
}

impl Wallets for Chain {
    fn wallet_having_identity_credit_funding_registration_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        self.wallets
            .iter()
            .find_map(|&wallet|
                wallet.index_of_identity_credit_funding_registration_hash(hash)
                    .map(|index| (wallet, index)))
    }

    fn wallet_having_identity_credit_funding_topup_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        self.wallets
            .iter()
            .find_map(|&wallet|
                wallet.index_of_identity_credit_funding_topup_hash(hash)
                    .map(|index| (wallet, index)))
    }

    fn wallet_having_identity_credit_funding_invitation_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        self.wallets
            .iter()
            .find_map(|&wallet|
                wallet.index_of_identity_credit_funding_invitation_hash(hash)
                    .map(|index| (wallet, index)))
    }

    fn wallet_having_provider_voting_authentication_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        self.wallets
            .iter()
            .find_map(|&wallet|
                wallet.index_of_provider_voting_authentication_hash(hash)
                    .map(|index| (wallet, index)))
    }

    fn wallet_having_provider_owner_authentication_hash(&self, hash: &UInt160) -> Option<(&Wallet, u32)> {
        self.wallets
            .iter()
            .find_map(|&wallet|
                wallet.index_of_provider_owning_authentication_hash(hash)
                    .map(|index| (wallet, index)))
   }

    fn wallet_having_provider_operator_authentication_key(&self, key: &UInt384) -> Option<(&Wallet, u32)> {
        self.wallets
            .iter()
            .find_map(|&wallet|
                wallet.index_of_provider_operator_authentication_key(key)
                    .map(|index| (wallet, index)))
    }

    fn wallet_containing_masternode_holding_address_for_provider_registration_transaction(&self, transaction: &ProviderRegistrationTransaction) -> Option<(&Wallet, u32)> {
        self.wallets
            .iter()
            .find_map(|&wallet|
                transaction.outputs()
                    .iter()
                    .find_map(|output|
                        output.address.and_then(|a| wallet.index_of_holding_address(&a))
                            .map(|index| (wallet, index))))
    }

}
