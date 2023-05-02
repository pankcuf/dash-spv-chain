use std::collections::HashSet;
use crate::chain::chain::Chain;
use crate::chain::tx::transaction::ITransaction;
use crate::derivation::derivation_path::{DerivationPath, IDerivationPath};
use crate::derivation::simple_indexed_derivation_path::{ISimpleIndexedDerivationPath, SimpleIndexedDerivationPath};
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::{UInt160, UInt256};
use crate::derivation::derivation_path_feature_purpose::DerivationPathFeaturePurpose;
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::index_path::IndexPath;
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::storage::manager::managed_context::ManagedContext;

#[derive(Debug, Default, PartialEq)]
pub struct MasternodeHoldingsDerivationPath {
    pub base: SimpleIndexedDerivationPath,
}

impl IDerivationPath for MasternodeHoldingsDerivationPath {
    fn chain(&self) -> &Chain {
        self.base.chain()
    }

    fn wallet(&self) -> Option<&Wallet> {
        self.base.wallet()
    }

    fn context(&self) -> &ManagedContext {
        self.base.context()
    }

    fn signing_algorithm(&self) -> KeyType {
        self.base.signing_algorithm()
    }

    fn reference(&self) -> &DerivationPathReference {
        self.base.reference()
    }

    fn extended_public_key(&mut self) -> Option<&dyn IKey> {
        self.base.extended_public_key()
    }

    fn has_extended_public_key(&self) -> bool {
        self.base.has_extended_public_key()
    }

    fn all_addresses(&self) -> HashSet<String> {
        self.base.all_addresses()
    }

    fn used_addresses(&self) -> HashSet<String> {
        self.base.used_addresses()
    }

    fn string_representation(&mut self) -> &str {
        self.base.string_representation()
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.base.standalone_extended_public_key_unique_id()
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::MasternodeHoldings
    }

    fn balance(&self) -> u64 {
        self.base.balance()
    }

    fn set_balance(&mut self, amount: u64) {
        self.base.set_balance(amount);
    }

    fn private_key_at_index_path_from_seed<KEY: IKey>(&self, index_path: &IndexPath<u32>, seed: &Vec<u8>) -> Option<KEY> where Self: Sized {
        self.base.private_key_at_index_path_from_seed(index_path, seed)
    }

    fn index_path_for_known_address(&self, address: &String) -> Option<IndexPath<u32>> {
        self.base.index_path_for_known_address(address)
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.base.generate_extended_public_key_from_seed(seed, wallet_unique_id)
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        self.base.register_transaction_address(address)
    }
}

impl ISimpleIndexedDerivationPath for MasternodeHoldingsDerivationPath {

    fn base(&self) -> &dyn IDerivationPath {
        &self.base
    }

    fn addresses_to_index_using_cache(&mut self, index: u32, use_cache: bool, add_to_cache: bool) -> HashSet<String> {
        self.base.addresses_to_index_using_cache(index, use_cache, add_to_cache)
    }

    fn index_of_known_address(&self, address: &String) -> Option<u32> {
        self.base.index_of_known_address(address)
    }

    fn index_of_known_address_hash_for_chain(&self, hash: &UInt160, chain: &Chain) -> Option<u32> {
        self.base.index_of_known_address_hash_for_chain(hash, chain)
    }

    fn public_key_data_at_index(&mut self, index: u32) -> Option<Vec<u8>> {
        self.base.public_key_data_at_index(index)
    }

    fn default_gap_limit(&self) -> u32 {
        5
    }
}


impl MasternodeHoldingsDerivationPath {

    pub fn provider_funds_derivation_path_for_chain(chain: &Chain) -> Self {
        let indexes = vec![
            DerivationPathFeaturePurpose::Default.into_u256(),
            UInt256::from(chain.r#type().coin_type()),
            UInt256::from(3u64),
            UInt256::from(0u64),
        ];
        let hardened = vec![true, true, true, true];
        Self {
            base: SimpleIndexedDerivationPath {
                base: DerivationPath::derivation_path_with_indexes(indexes, hardened, DerivationPathType::ProtectedFunds, KeyType::ECDSA, DerivationPathReference::ProviderFunds, chain),
                ..Default::default()
            }
        }
    }

    pub fn provider_funds_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        let mut path = Self::provider_funds_derivation_path_for_chain(&wallet.chain);
        path.base.base.wallet = Some(wallet);
        path
    }

    pub fn receive_address(&mut self) -> Option<&String> {
        match self.register_addresses_with_gap_limit(1) {
            Ok(addresses) => addresses.last(),
            Err(..) => self.base.ordered_addresses.last()
        }
    }

    // sign any inputs in the given transaction that can be signed using private keys from the wallet
    /*pub fn sign_transaction(&self, transaction: &mut dyn ITransaction, authprompt: Option<String>) -> Result<(bool, bool), util::Error> {
        if transaction.input_addresses().len() != 1 {
            return Ok((false, false));
        }
        if let Some(first_input_address) = transaction.input_addresses().first() {
            if let Some(index) = self.index_of_known_address(first_input_address) {
                let seed_completion: SeedCompletionBlock = |seed, cancelled| {
                    if let Some(seed) = seed {
                        if let Some(key) = self.private_key_at_index::<ECDSAKey>(index, &seed) {
                            // completion(transaction.sign_with_private_keys(vec![key]), false);
                            return Ok((transaction.sign_with_private_keys(vec![key]), false));
                        }
                    }
                    completion(false, cancelled);
                };
                if let Some(wallet) = self.wallet() {
                    if let Some(request) = wallet.seed_request_block {
                        request(authprompt, MASTERNODE_COST, seed_completion);
                    }
                }
            }
        }
    }*/
}
