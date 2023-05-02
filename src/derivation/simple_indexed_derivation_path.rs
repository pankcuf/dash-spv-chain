use std::collections::HashSet;
use std::ops::Range;
use crate::chain::chain::Chain;
use crate::chain::ext::settings::Settings;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::UInt160;
use crate::derivation::derivation_path::{DerivationPath, IDerivationPath};
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::util;
use crate::util::address::Address;

pub trait ISimpleIndexedDerivationPath: IDerivationPath {
    fn base(&self) -> &dyn IDerivationPath;
    /// gets addresses to an index, does not use cache and does not add to cache
    fn addresses_to_index(&mut self, index: u32) -> HashSet<String> {
        self.addresses_to_index_using_cache(index, false, false)
    }
    /// gets addresses to an index, does not use cache and does not add to cache
    fn addresses_to_index_using_cache(&mut self, index: u32, use_cache: bool, add_to_cache: bool) -> HashSet<String>;
    /// gets an address at an index
    fn address_at_index(&mut self, index: u32) -> Option<String> {
        self.address_at_index_path(&IndexPath::index_path_with_index(index))
    }
    /// true if the address at the index was previously used as an input or output in any wallet transaction
    fn address_is_used_at_index(&mut self, index: u32) -> bool {
        self.address_is_used_at_index_path(&IndexPath::index_path_with_index(index))
    }
    /// returns the index of an address in the derivation path as long as it is within the gap limit
    fn index_of_known_address(&self, address: &String) -> Option<u32>;
    fn index_of_known_address_hash_for_chain(&self, hash: &UInt160, chain: &Chain) -> Option<u32>;
    /// gets a public key at an index
    fn public_key_data_at_index(&mut self, index: u32) -> Option<Vec<u8>> {
        self.public_key_data_at_index_path(&IndexPath::index_path_with_index(index))
    }
    /// gets public keys to an index as Vec<u8>
    fn public_key_data_array_to_index(&mut self, index: u32) -> Vec<Vec<u8>> {
        (0..index).filter_map(|i| self.public_key_data_at_index(i)).collect()
    }

    // /// gets a private key at an index
    // fn private_key_at_index(&self, index: u32, seed: &Vec<u8>) -> Option<&dyn IKey> {
    //     self.private_key_at_index_path_from_seed(&IndexPath::index_path_with_index(index), seed)
    // }
    /// get private keys for a range or to an index
    fn private_keys_to_index<KEY: IKey>(&self, index: u32, seed: &Vec<u8>) -> Vec<KEY> where Self: IIndexPath {
        self.private_keys_for_range(0..index, seed)
    }
    fn private_keys_for_range<KEY: IKey>(&self, range: Range<u32>, seed: &Vec<u8>) -> Vec<KEY> where Self: IIndexPath {
        range.filter_map(|i| self.private_key_at_index(i, seed)).collect()
    }
    fn default_gap_limit(&self) -> u32 {
        10
    }
    /// update addresses
    fn register_addresses_with_default_gap_limit(&mut self) -> Result<Vec<String>, util::Error> {
        self.register_addresses_with_gap_limit(self.default_gap_limit())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SimpleIndexedDerivationPath {
    pub base: DerivationPath,
    pub ordered_addresses: Vec<String>,
}

impl IDerivationPath for SimpleIndexedDerivationPath {
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

    fn load_addresses(&mut self) {
        if !self.base.addresses_loaded {
            self.context().perform_block_and_wait(|context| {
                match DerivationPathEntity::aggregate_addresses_with_their_relationships(self, context) {
                    Ok((entity, mut addresses)) => {
                        self.base.sync_block_height = entity.sync_block_height as u32;
                        addresses.sort_by_key(|(addr, _)| addr.index);
                        addresses.iter().for_each(|(e, used_in_relationships)| {
                            // todo: do we need store nulls??
                            // while (e.index >= self.mOrderedAddresses.count)
                            //  [self.mOrderedAddresses addObject:[NSNull null]];
                            if Address::is_valid_dash_address_for_script_map(&e.address, self.chain().script()) {
                                self.ordered_addresses.push(e.address.clone());
                                self.base.all_addresses.push(e.address.clone());
                                if *used_in_relationships {
                                    self.base.used_addresses.push(e.address.clone());
                                }
                            }
                        });

                    },
                    Err(_) => panic!("Can't load addresses for path")
                }
            });
            self.base.addresses_loaded = true;
            self.register_addresses_with_gap_limit(10)
                .expect("");
        }
    }

    fn reload_addresses(&mut self) {
        self.base.all_addresses.clear();
        self.ordered_addresses.clear();
        self.base.used_addresses.clear();
        self.base.addresses_loaded = false;
        self.load_addresses();
    }

    fn string_representation(&mut self) -> &str {
        self.base.string_representation()
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.base.standalone_extended_public_key_unique_id()
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::SimpleIndexed
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
        self.index_of_known_address(address).map(|index| IndexPath::index_path_with_index(index))
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.base.generate_extended_public_key_from_seed(seed, wallet_unique_id)
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        // todo: avoid clone & optioning address
        let contains = self.contains_address(address);
        if contains && !self.used_addresses().contains(address) {
            self.used_addresses().insert(address.clone());
            let _ = self.register_addresses_with_default_gap_limit();
        }
        contains
    }

    // Wallets are composed of chains of addresses. Each chain is traversed until a gap of a certain number of addresses is
    // found that haven't been used in any transactions. This method returns an array of <gapLimit> unused addresses
    // following the last used address in the chain.
    fn register_addresses_with_gap_limit(&mut self, gap_limit: u32) -> Result<Vec<String>, util::Error> {
        assert_ne!(self.base.r#type, DerivationPathType::MultipleUserAuthentication, "This should not be called for multiple user authentication. Use 'register_addresses_with_gap_limit_and_identity_index()'' instead.");
        let mut array = self.ordered_addresses.clone();
        let wallet = self.wallet();
        if wallet.is_none() || !wallet.unwrap().is_transient {
            assert!(self.base.addresses_loaded, "addresses must be loaded before calling this function");
        }
        let wallet = wallet.unwrap();
        let mut i = array.len();
        // keep only the trailing contiguous block of addresses that aren't used
        while i > 0 && !self.used_addresses().contains(array.get(i - 1).unwrap()) {
            i -= 1;
        }
        if i > 0 {
            array.drain(0..i);
        }
        let limit = gap_limit as usize;
        if array.len() >= limit {
            return Ok(array.drain(0..limit).collect());
        }
        // It seems weird to repeat this, but it's correct because of the original call receive address and change address
        array = self.ordered_addresses.clone();
        i = array.len();
        let mut n = i as u32;
        // keep only the trailing contiguous block of addresses with no transactions
        while i > 0 && !self.used_addresses().contains(array.get(i - 1).unwrap()) {
            i -= 1;
        }
        if i > 0 {
            array.drain(0..i);
            if array.len() >= limit {
                return Ok(array.drain(0..limit).collect());
            }
        }
        while array.len() < limit {
            // generate new addresses up to gapLimit
            if let Some(pub_key) = self.public_key_data_at_index(n) {
                let addr = Address::with_public_key_data(&pub_key, self.base.chain.script());
                if !wallet.is_transient {
                    match DerivationPathEntity::derivation_path_entity_matching_derivation_path(self, self.base.context) {
                        Ok(derivationPathEntity) => {
                            // store new address in core data
                            AddressEntity::create_with(derivationPathEntity.id, addr.as_str(), n as i32, false, false, self.base.context)
                                .expect("Can't store address entity");
                        },
                        Err(err) => {
                            return Err(util::Error::Default(format!("Can't retrieve derivation path entity for {:?}", self)));
                        }
                    }
                }
                self.base.all_addresses.push(addr);
                array.push(addr.clone());
                self.ordered_addresses.push(addr.clone());
                n += 1;
            }
        }
        Ok(array)
    }
}

impl ISimpleIndexedDerivationPath for SimpleIndexedDerivationPath {
    fn base(&self) -> &dyn IDerivationPath {
        &self.base
    }

    fn addresses_to_index_using_cache(&mut self, index: u32, use_cache: bool, add_to_cache: bool) -> HashSet<String> {
        let mut arr = HashSet::<String>::new();
        (0..index).for_each(|i| {
            let idx = i as usize;
            if use_cache && self.ordered_addresses.len() > idx && self.ordered_addresses.get(idx).is_some() {
                arr.insert(self.ordered_addresses[idx].clone());
            } else if let Some(pubkey) = self.public_key_data_at_index(i) {
                let addr = Address::with_public_key_data(&pubkey, self.chain().script());
                arr.insert(addr);
                if add_to_cache && self.ordered_addresses.len() == idx {
                    self.ordered_addresses.push(addr.clone());
                }
            }
        });
        arr
    }

    fn index_of_known_address(&self, address: &String) -> Option<u32> {
        self.ordered_addresses.iter().position(|x| x == address).map(|pos| pos as u32)
    }

    fn index_of_known_address_hash_for_chain(&self, hash: &UInt160, chain: &Chain) -> Option<u32> {
        let address = Address::from_hash160_for_script_map(hash, chain.script());
        self.index_of_known_address(&address)
    }

}

impl SimpleIndexedDerivationPath {

    /// returns the index of the first unused Address;
    pub fn first_unused_index(&self) -> u32 {
        let mut i = self.ordered_addresses.len();
        // keep only the trailing contiguous block of addresses that aren't used
        while i > 0 &&
            self.ordered_addresses.get(i - 1).is_some() &&
            !self.used_addresses().contains(self.ordered_addresses.get(i - 1).unwrap()) {
            i -= 1;
        }
        i as u32
    }

}
