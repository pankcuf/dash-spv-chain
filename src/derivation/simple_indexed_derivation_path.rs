use std::collections::HashSet;
use std::ops::Range;
use crate::chain::chain::Chain;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::UInt160;
use crate::derivation::derivation_path;
use crate::derivation::derivation_path::{DerivationPath, DerivationPathKind, Error, IDerivationPath};
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::uint256_index_path::{IIndexPath, IndexPath};
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::util;
use crate::util::crypto::{address_from_hash160_for_chain, address_with_public_key_data};

pub trait ISimpleIndexedDerivationPath: IDerivationPath {
    fn addresses_to_index(&self, index: u32) -> HashSet<String>;
    fn addresses_to_index_using_cache(&self, index: u32, use_cache: bool, add_to_cache: bool) -> HashSet<String>;
    fn address_at_index(&self, index: u32) -> Option<String>;
    /// true if the address at the index was previously used as an input or output in any wallet transaction
    fn address_is_used_at_index(&self, index: u32) -> bool;
    fn index_path_of_known_address(&self, address: String) -> Option<dyn IIndexPath>;
    /// returns the index of an address in the derivation path as long as it is within the gap limit
    fn index_of_known_address(&self, address: Option<String>) -> Option<u32>;
    fn index_of_known_address_hash_for_chain(&self, hash: &UInt160, chain: &Chain) -> Option<u32>;
    /// gets a public key at an index
    fn public_key_data_at_index(&self, index: u32) -> Option<Vec<u8>>;
}

#[derive(Clone, Copy, Debug)]
pub struct SimpleIndexedDerivationPath {
    pub base: DerivationPath,
    pub ordered_addresses: Vec<String>,
}

impl IDerivationPath for SimpleIndexedDerivationPath {
    fn wallet(&self) -> Option<&Wallet> {
        self.base.wallet()
    }

    fn signing_algorithm(&self) -> &KeyType {
        self.base.signing_algorithm()
    }

    fn reference(&self) -> &DerivationPathReference {
        self.base.reference()
    }

    fn is_derivation_path_equal(&self, other: &dyn IDerivationPath) -> bool {
        self.base.is_derivation_path_equal(other)
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

    fn contains_address(&self, address: Option<String>) -> bool {
        self.base.contains_address(address)
    }

    fn address_is_used(&self, address: Option<String>) -> bool {
        self.base.address_is_used(address)
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.base.standalone_extended_public_key_unique_id()
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::SimpleIndexed
    }

    fn balance(&self) -> u64 {
       self.base.balance
    }

    fn private_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        todo!()
    }

    fn public_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        self.public_key_at_index_path(index_path)
    }

    fn base_index_path<T>(&self) -> IndexPath<T> {
        self.base.base_index_path()
    }

    fn index_path_for_known_address<T>(&self, address: Option<String>) -> Option<IndexPath<T>> {
        todo!()
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        todo!()
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        // todo: avoid clone & optioning address
        if self.contains_address(Some(address.clone())) {
            if !self.used_addresses.contains(address) {
                self.used_addresses.push(address.clone());
                let _ = self.register_addresses_with_default_gap_limit();
            }
            true
        }
        false
    }

    fn register_addresses_with_gap_limit(&mut self, gap_limit: u32) -> Result<Vec<String>, util::Error> {
        assert_ne!(self.kind(), DerivationPathType::MultipleUserAuthentication, "This should not be called for multiple user authentication. Use 'register_addresses_with_gap_limit_and_identity_index()'' instead.");
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
        if array.len() >= gap_limit as usize {
            return Ok(array.drain(0..gap_limit).collect());
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
            if array.len() >= gap_limit as usize {
                return Ok(array.drain(0..gap_limit).collect());
            }
        }
        while array.len() < gap_limit as usize {
            // generate new addresses up to gapLimit
            if let Some(pub_key) = self.public_key_data_at_index(n) {
                if let Some(addr) = address_with_public_key_data(&pub_key, self.base.chain) {
                    if !wallet.is_transient {
                        match DerivationPathEntity::derivation_path_entity_matching_derivation_path(self, self.base.context) {
                            Ok(derivationPathEntity) => {
                                // store new address in core data
                                AddressEntity::create_with(derivationPathEntity.id, addr.as_str(), n as i32, false, false, self.base.context)
                            },
                            Err(err) => Err(Error::Default(&format!("Can't retrieve derivation path entity for {:?}", self)))
                        }
                    }
                    self.base.all_addresses.push(addr);
                    array.push(addr.clone());
                    self.ordered_addresses.push(addr.clone());
                    n += 1;

                } else {
                    println!("error generating keys");
                    return Err(util::Error::DefaultWithCode(&format!("Error generating public keys"), 500));
                }
            }
        }
        Ok(array)
    }
}

impl ISimpleIndexedDerivationPath for SimpleIndexedDerivationPath {
    /// gets addresses to an index, does not use cache and does not add to cache
    fn addresses_to_index(&self, index: u32) -> HashSet<String> {
        todo!()
    }

    /// gets addresses to an index, does not use cache and does not add to cache
    fn addresses_to_index_using_cache(&self, index: u32, use_cache: bool, add_to_cache: bool) -> HashSet<String> {
        todo!()
    }

    fn address_at_index(&self, index: u32) -> Option<String> {
        todo!()
        // self.base.address_at_index_path(IndexPath)
        // return [self addressAtIndexPath:[NSIndexPath indexPathWithIndex:index]];
    }

    fn address_is_used_at_index(&self, index: u32) -> bool {
        todo!()
    }

    fn index_path_of_known_address(&self, address: String) -> Option<dyn IIndexPath> {
        todo!()
    }

    fn index_of_known_address(&self, address: Option<String>) -> Option<u32> {
        if let Some(address) = address {
            if let Some(pos) = self.ordered_addresses.iter().position(|x| x == &address) {
                return Some(pos as u32);
            }
        }
        None
    }

    fn index_of_known_address_hash_for_chain(&self, hash: &UInt160, chain: &Chain) -> Option<u32> {
        let address = address_from_hash160_for_chain(hash, chain);
        self.index_of_known_address(address)
    }

    fn public_key_data_at_index(&self, index: u32) -> Option<Vec<u8>> {
        todo!()
    }

}

impl SimpleIndexedDerivationPath {


    /// returns the index of the first unused Address;
    pub fn first_unused_index(&self) -> u32 {
        todo!()
    }

    /// gets public keys to an index as NSData
    pub fn public_key_data_array_to_index(&self, index: u32) -> Vec<Vec<u8>> {
        todo!()
    }

    /// gets a private key at an index
    pub fn private_key_at_index(&self, index: u32, from_seed: Vec<u8>) -> DSKey {
        todo!()
    }

    /// get private keys for a range or to an index
    pub fn private_keys_to_index(&self, index: u32, from_seed: Vec<u8>) -> Vec<DSKey> {
        todo!()
    }

    pub fn private_keys_for_range(&self, range: Range<u32>, from_seed: Vec<u8>) -> Vec<DSKey> {
        todo!()
    }

    /// update addresses
    pub fn register_addresses_with_default_gap_limit(&self) -> Result<Vec<String>, util::Error> {
        todo!()
    }
}
