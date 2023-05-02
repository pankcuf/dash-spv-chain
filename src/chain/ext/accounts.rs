use crate::crypto::UInt256;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::chain::Chain;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::wallet::Wallet;

pub trait Accounts {
    fn balance(&mut self) -> u64;
    fn first_account_with_balance(&self) -> Option<&Account>;
    fn first_account_that_can_contain_transaction(&self, transaction: &dyn ITransaction) -> Option<&Account>;
    fn accounts_that_can_contain_transaction(&self, transaction: &dyn ITransaction) -> Vec<&Account>;
    fn account_containing_address(&self, address: &String) -> Option<&Account>;
    fn account_containing_dashpay_external_derivation_path_address(&self, address: &String) -> Option<&Account>;
    fn first_account_for_transaction_hash(&self, tx_hash: &UInt256) -> Option<(&Wallet, &Account, &dyn ITransaction)>;
    fn accounts_for_transaction_hash(&self, tx_hash: &UInt256) -> Option<(Vec<&Account>, &dyn ITransaction)>;
}

impl Accounts for Chain {
    fn balance(&mut self) -> u64 {
        self.wallets
            .iter()
            .map(|wallet| wallet.balance())
            .chain(self.standalone_derivation_paths()
                .iter()
                .map(|path| path.balance()))
            .sum()
    }

    fn first_account_with_balance(&self) -> Option<&Account> {
        self.wallets
            .iter()
            .find_map(|wallet| wallet.first_account_with_balance())
    }

    fn first_account_that_can_contain_transaction(&self, transaction: &dyn ITransaction) -> Option<&Account> {
        self.wallets
            .iter()
            .find_map(|wallet| wallet.first_account_that_can_contain_transaction(transaction))
    }

    fn accounts_that_can_contain_transaction(&self, transaction: &dyn ITransaction) -> Vec<&Account> {
        self.wallets
            .iter()
            .fold(Vec::new(), |mut accounts, wallet|{
                accounts.extend(wallet.accounts_that_can_contain_transaction(transaction));
                accounts
            })
    }

    fn account_containing_address(&self, address: &String) -> Option<&Account> {
        self.wallets
            .iter()
            .find_map(|wallet| wallet.account_for_address(address))
    }

    fn account_containing_dashpay_external_derivation_path_address(&self, address: &String) -> Option<&Account> {
        self.wallets
            .iter()
            .find_map(|wallet| wallet.account_for_dashpay_external_derivation_path_address(address))
    }

    /// returns an account to which the given transaction hash is associated with, no account if the transaction hash is not associated with the wallet
    fn first_account_for_transaction_hash(&self, tx_hash: &UInt256) -> Option<(&Wallet, &Account, &dyn ITransaction)> {
        self.wallets.iter().find_map(|&wallet|
            wallet.accounts.values().find_map(|account| {
                if let Some(tx) = account.transaction_for_hash(tx_hash) {
                    Some((wallet, account, tx))
                } else {
                    None
                }
        }))
    }

    /// returns an account to which the given transaction hash is associated with, no account if the transaction hash is not associated with the wallet
    fn accounts_for_transaction_hash(&self, tx_hash: &UInt256) -> Option<(Vec<&Account>, &dyn ITransaction)> {
        let mut accounts = Vec::<&Account>::new();
        let mut transaction: Option<&dyn ITransaction> = None;
        self.wallets.iter().for_each(|wallet| {
            wallet.accounts.values().for_each(|account| {
                if let Some(tx) = account.transaction_for_hash(tx_hash) {
                    transaction = Some(tx);
                    accounts.push(account);
                }
            });
        });
        if let Some(tx) = transaction {
            Some((accounts, tx))
        } else {
            None
        }
    }

}
