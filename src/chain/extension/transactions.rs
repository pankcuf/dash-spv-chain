use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::chain::extension::accounts::Accounts;
use crate::chain::extension::wallets::Wallets;
use crate::chain::tx::transaction_type::TransactionType;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::tx::provider_registration_transaction::ProviderRegistrationTransaction;
use crate::chain::tx::provider_update_registrar_transaction::ProviderUpdateRegistrarTransaction;
use crate::chain::tx::provider_update_revocation_transaction::ProviderUpdateRevocationTransaction;
use crate::chain::tx::provider_update_service_transaction::ProviderUpdateServiceTransaction;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::tx::transaction_direction::TransactionDirection;
use crate::chain::wallet::extension::identities::WalletIdentities;
use crate::chain::wallet::extension::invitations::WalletInvitations;
use crate::chain::wallet::wallet::Wallet;
use crate::platform::identity::identity::Identity;
use crate::platform::identity::invitation::Invitation;

pub trait Transactions {
    fn transaction_for_hash(&self, hash: &UInt256) -> Option<&dyn ITransaction>;
    fn transaction_and_wallet_for_hash(&self, hash: &UInt256) -> Option<(&Wallet, &dyn ITransaction)>;
    fn all_transactions(&self) -> Vec<&dyn ITransaction>;
    /// The amount sent globally by the transaction (total wallet outputs consumed, change and fee included)
    fn amount_received_from_transaction(&self, transaction: &dyn ITransaction) -> u64;
    /// The amount sent globally by the transaction (total wallet outputs consumed, change and fee included)
    fn amount_sent_by_transaction(&self, transaction: &dyn ITransaction) -> u64;

    fn direction_of_transaction(&self, transaction: &dyn ITransaction) -> TransactionDirection;
    fn trigger_updates_for_local_references(&self, transaction: &dyn ITransaction);
}

impl Transactions for Chain {
    fn transaction_for_hash(&self, hash: &UInt256) -> Option<&dyn ITransaction> {
        if let Some((tx, _wallet)) = self.transaction_and_wallet_for_hash(hash) {
            Some(tx)
        } else {
            None
        }
    }

    fn transaction_and_wallet_for_hash(&self, hash: &UInt256) -> Option<(&Wallet, &dyn ITransaction)> {
        self.wallets.iter().find_map(|&wallet|
            wallet.accounts.values().find_map(|account| {
                if let Some(tx) = account.transaction_for_hash(hash) {
                    Some((wallet, tx))
                } else {
                    None
                }
            }))
    }

    fn all_transactions(&self) -> Vec<&dyn ITransaction> {
        self.wallets.iter().fold(Vec::new(), |mut transactions, wallet| {
            transactions.extend(wallet.all_transactions());
            transactions
        })
    }

    fn amount_received_from_transaction(&self, transaction: &dyn ITransaction) -> u64 {
        self.wallets
            .iter()
            .map(|wallet| wallet.amount_received_from_transaction(transaction))
            .sum()
    }

    fn amount_sent_by_transaction(&self, transaction: &dyn ITransaction) -> u64 {
        self.wallets
            .iter()
            .map(|wallet| wallet.amount_sent_by_transaction(transaction))
            .sum()
    }

    fn direction_of_transaction(&self, transaction: &dyn ITransaction) -> TransactionDirection {
        let sent = self.amount_sent_by_transaction(transaction);
        let received = self.amount_received_from_transaction(transaction);
        let fee = if let Some(acc) = self.first_account_that_can_contain_transaction(transaction) {
            acc.fee_for_transaction(transaction)
        } else {
            0
        };
        if sent > 0 && (received + fee) == sent {
            TransactionDirection::Moved
        } else if sent > 0 {
            TransactionDirection::Sent
        } else if received > 0 {
            TransactionDirection::Received
        } else {
            TransactionDirection::NotAccountFunds
        }
    }

    fn trigger_updates_for_local_references(&self, transaction: &dyn ITransaction) {
        match transaction.r#type() {
            TransactionType::ProviderRegistration => {
                let tx = transaction as ProviderRegistrationTransaction;
                if self.wallet_having_provider_owner_authentication_hash(&tx.owner_key_hash).is_some() ||
                    self.wallet_having_provider_voting_authentication_hash(&tx.voting_key_hash).is_some() ||
                    self.wallet_having_provider_operator_authentication_key(&tx.operator_key).is_some() {
                    self.masternode_manager().local_masternode_from_provider_registration_transaction(&tx, true);
                }
            },
            TransactionType::ProviderUpdateService => {
                let tx = transaction as ProviderUpdateServiceTransaction;
                if let Some(mut local_masternode) = self.masternode_manager().local_masternode_having_provider_registration_transaction_hash(&tx.provider_registration_transaction_hash) {
                    local_masternode.update_with_update_service_transaction(tx, true);
                }
            },
            TransactionType::ProviderUpdateRegistrar => {
                let tx = transaction as ProviderUpdateRegistrarTransaction;
                if let Some(mut local_masternode) = self.masternode_manager().local_masternode_having_provider_registration_transaction_hash(&tx.provider_registration_transaction_hash) {
                    local_masternode.update_with_update_registrar_transaction(tx, true);
                }
            },
            TransactionType::ProviderUpdateRevocation => {
                let tx = transaction as ProviderUpdateRevocationTransaction;
                if let Some(mut local_masternode) = self.masternode_manager().local_masternode_having_provider_registration_transaction_hash(&tx.provider_registration_transaction_hash) {
                    local_masternode.update_with_update_revocation_transaction(tx, true);
                }
            },
            TransactionType::CreditFunding => {
                let tx = transaction as CreditFundingTransaction;
                if let Some((wallet, index)) = self.wallet_having_blockchain_identity_credit_funding_registration_hash(tx.credit_burn_public_key_hash()) {
                    let identity = wallet.blockchain_identity_for_unique_id(tx.credit_burn_identity_identifier());
                    if identity.is_none() {
                        let mut identity = Identity::init_at_with_credit_funding_transaction_and_username_dictionary(index, &tx, None, wallet);
                        identity.register_in_wallet_for_registration_funding_transaction(tx);
                    }
                } else if let Some((wallet, index)) = self.wallet_having_blockchain_identity_credit_funding_invitation_hash(&tx.credit_burn_public_key_hash()) {
                    let invitation = wallet.blockchain_invitation_for_unique_id(tx.credit_burn_identity_identifier);
                    if invitation.is_none() {
                        let mut invitation = Invitation::init_at_with_funding_transaction(index, &tx, wallet);
                        invitation.register_in_wallet_for_registration_funding_transaction(tx);
                    }
                }
            }

            _ => {}
        }
    }

}
