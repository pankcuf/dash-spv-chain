use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::chain::ext::accounts::Accounts;
use crate::chain::tx::{ITransaction, TransactionDirection};
use crate::chain::wallet::wallet::Wallet;

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
        if let Some((_, tx)) = self.transaction_and_wallet_for_hash(hash) {
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
        transaction.trigger_updates_for_local_references();
    }

}
