use std::collections::{HashMap, HashSet};
use libp2p::futures::StreamExt;
use secp256k1::rand::{Rng, thread_rng};
use crate::chain::network::peer::{DAY_TIME_INTERVAL, HOUR_TIME_INTERVAL};
use crate::crypto::UInt256;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::tx::transaction_type::TransactionType;
use crate::derivation;
use crate::derivation::derivation_path::IDerivationPath;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::tx::provider_registration_transaction::ProviderRegistrationTransaction;
use crate::chain::tx::provider_update_registrar_transaction::ProviderUpdateRegistrarTransaction;
use crate::chain::tx::provider_update_revocation_transaction::ProviderUpdateRevocationTransaction;
use crate::chain::tx::provider_update_service_transaction::ProviderUpdateServiceTransaction;
use crate::chain::wallet::bip39_mnemonic::{BIP39_CREATION_TIME, BIP39_WALLET_UNKNOWN_CREATION_TIME};
use crate::chain::wallet::wallet::Wallet;
use crate::storage::manager::managed_context::ManagedContext;

pub struct SpecialTransactionWalletHolder {
    wallet: &'static Wallet,
    provider_registration_transactions: HashMap<UInt256, ProviderRegistrationTransaction>,
    provider_update_service_transactions: HashMap<UInt256, ProviderUpdateServiceTransaction>,
    provider_update_registrar_transactions: HashMap<UInt256, ProviderUpdateRegistrarTransaction>,
    provider_update_revocation_transactions: HashMap<UInt256, ProviderUpdateRevocationTransaction>,
    credit_funding_transactions: HashMap<UInt256, CreditFundingTransaction>,
    transactions_to_save: Vec<dyn ITransaction>,
    transactions_to_save_in_block_save: HashMap<u32, Vec<dyn ITransaction>>,

   // @property (nonatomic, strong) NSManagedObjectContext *managedObjectContext;
    context: &'static ManagedContext,
}

impl SpecialTransactionWalletHolder {
    pub fn init_with_wallet(wallet: &Wallet, context: &ManagedContext) -> Self {
        let mut s = Self {
            wallet,
            context,
            ..Default::default()
        };
        s.load_transactions();
        s
    }

    pub fn transaction_dictionaries(&self) -> Vec<HashMap<UInt256, dyn ITransaction>> {
        vec![self.provider_registration_transactions, self.provider_update_service_transactions, self.provider_update_registrar_transactions, self.provider_update_revocation_transactions, self.credit_funding_transactions]
    }

    pub fn all_transactions(&self) -> HashSet<dyn ITransaction> {
        self.transaction_dictionaries().iter().fold(HashSet::new(), |mut arr, dict| {
            arr.extend(dict.values());
            arr
        })
    }

    pub fn all_transactions_count(&self) -> usize {
        self.transaction_dictionaries().iter().map(|dict| dict.len()).sum()
    }

    pub fn derivation_paths(&self) -> Vec<dyn IDerivationPath> {
        self.wallet.chain.derivation_path_factory.unloaded_specialized_derivation_paths_for_wallet(&self.wallet)
    }

    pub fn transaction_for_hash(&self, hash: &UInt256) -> Option<&dyn ITransaction> {
        self.transaction_dictionaries().get(hash)
    }

    pub fn set_wallet(&mut self, wallet: Wallet) {
        assert!(self.wallet.is_none(), "this should only be called during initialization");
        if self.wallet.is_some() {
            return;
        }
        self.wallet = &wallet;
        self.load_transactions();
    }

    pub fn remove_all_transactions(&self) {
        self.transaction_dictionaries().iter().for_each(|mut dict| {
            dict.clear();
        })
    }
    pub fn prepare_for_incoming_transaction_persistence_for_block_save_with_number(&mut self, block_number: u32) {
        self.transactions_to_save_in_block_save.insert(block_number, self.transactions_to_save.clone());
        self.transactions_to_save.clear()
    }

    pub fn persist_incoming_transactions_attributes_for_block_save_with_number(&mut self, block_number: u32/*, context: NSManagedObjectContext*/) {
        if let Some(transactions) = self.transactions_to_save_in_block_save.get(&block_number) {
            transactions.iter().for_each(|transaction| {
                //[transaction setInitialPersistentAttributesInContext:context];
            });
        }

        self.transactions_to_save_in_block_save.remove(&block_number);
    }

    pub fn register_transaction(&mut self, transaction: &dyn ITransaction, save_immediately: bool) -> bool {
        let mut added = false;
        let tx_hash = transaction.tx_hash();
        match transaction.r#type() {
            TransactionType::ProviderRegistration => {
                if self.provider_registration_transactions.get(&tx_hash).is_none() {
                    self.provider_registration_transactions.insert(tx_hash, transaction as ProviderRegistrationTransaction);
                    added = true;
                }
            },
            TransactionType::ProviderUpdateService => {
                if self.provider_update_service_transactions.get(&tx_hash).is_none() {
                    self.provider_update_service_transactions.insert(tx_hash, transaction as ProviderUpdateServiceTransaction);
                    added = true;
                }
            },
            TransactionType::ProviderUpdateRegistrar => {
                if self.provider_update_registrar_transactions.get(&tx_hash).is_none() {
                    self.provider_update_registrar_transactions.insert(tx_hash, transaction as ProviderUpdateRegistrarTransaction);
                    added = true;
                }
            },
            TransactionType::ProviderUpdateRevocation => {
                if self.provider_update_revocation_transactions.get(&tx_hash).is_none() {
                    self.provider_update_revocation_transactions.insert(tx_hash, transaction as ProviderUpdateRevocationTransaction);
                    added = true;
                }
            },
            TransactionType::CreditFunding => {
                let tx = transaction as CreditFundingTransaction;
                let credit_burn_identity_identifier = tx.credit_burn_identity_identifier();
                if self.credit_funding_transactions.get(&credit_burn_identity_identifier).is_none() {
                    self.credit_funding_transactions.insert(credit_burn_identity_identifier, tx);
                    added = true;
                }
            },
            _ => {
                assert!(false, "unknown transaction type being registered");
                return false;
            }
        }
        if added {
            if save_immediately {
                transaction.save_initial();
            } else {
                self.transactions_to_save.push(transaction);
            }
        }

        added
    }

    pub fn load_transactions(&self) {
        if self.wallet.is_transient { return; }
        self.context.perform_block_and_wait(|context| {
            // todo: load special transactions
        });
    }

    pub fn credit_funding_transaction_for_blockchain_identity_unique_id(&self, unique_id: &UInt256) -> Option<&CreditFundingTransaction> {
        self.credit_funding_transactions.get(unique_id)
    }

    /// set the block heights and timestamps for the given transactions, use a height of TX_UNCONFIRMED and timestamp of 0 to
    /// indicate a transaction and it's dependents should remain marked as unverified (not 0-conf safe)
    pub fn set_block_height(&mut self, height: u32, timestamp: f64, tx_hashes: Vec<UInt256>) -> Vec<&dyn ITransaction> {
        let wallet_creation_time = self.wallet.wallet_creation_time();
        tx_hashes.iter().filter_map(|hash| {
            if let Some(tx) = self.transaction_for_hash(hash) {
                if !(tx.block_height() == height && tx.timestamp() == timestamp) {
                    tx.set_block_height(height);
                    if tx.timestamp() == u32::MAX || tx.timestamp() == 0 {
                        // We should only update the timestamp one time
                        tx.set_timestamp(timestamp);
                    }
                    if wallet_creation_time == BIP39_WALLET_UNKNOWN_CREATION_TIME || wallet_creation_time == BIP39_CREATION_TIME {
                        self.wallet.set_guessed_wallet_creation_time(tx.timestamp() - HOUR_TIME_INTERVAL - (DAY_TIME_INTERVAL / thread_rng().gen() % DAY_TIME_INTERVAL));
                    }
                    return Some(tx);
                }
            }
            None
        }).collect()
    }


}
