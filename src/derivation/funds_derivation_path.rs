use std::collections::{HashMap, HashSet};
use std::ops::RangeBounds;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::chain::wallet::wallet::Wallet;
use crate::derivation::derivation_path;
use crate::derivation::derivation_path::{DerivationPath, DerivationPathKind, IDerivationPath, SequenceGapLimit};
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::uint256_index_path::{IIndexPath, IndexPath};
use crate::keychain::keychain::Keychain;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::util;
use crate::util::crypto::{address_with_public_key_data, is_valid_dash_address_on_chain};

const DERIVATION_PATH_IS_USED_KEY: &str = "DERIVATION_PATH_IS_USED_KEY";

pub trait IFundsDerivationPath {
    /// all previously generated external addresses
    fn all_receive_addresses(&self) -> Vec<String>;
}

pub struct FundsDerivationPath {
    pub base: DerivationPath,

    internal_addresses: HashSet<String>,
    external_addresses: HashSet<String>,

    is_for_first_account: bool,
    has_known_balance_internal: bool,
    checked_initial_has_known_balance: bool,
}

impl IDerivationPath for FundsDerivationPath {
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

    fn load_addresses(&mut self) {
        if !self.base.addresses_loaded {
            match DerivationPathEntity::derivation_path_entity_matching_derivation_path_with_addresses(self, self.context()) {
                Ok((entity, addresses, used_in_inputs, used_in_outputs)) => {
                    self.base.sync_block_height = entity.sync_block_height as u32;
                    for address in addresses {
                        let mut a = if address.internal.0 { self.internal_addresses.clone() } else { self.external_addresses.clone() };
                        let a_index = address.index as usize;
                        // todo: check if a is needed
                        while a_index >= a.len() {
                            a.insert(None);
                        }
                        if !is_valid_dash_address_on_chain(&address.address, self.base.account.unwrap().wallet.unwrap().chain) {
                            continue;
                        }
                        a[a_index] = address.address;
                        if !used_in_inputs.is_empty() || !used_in_outputs.is_empty() {
                            self.base.used_addresses.push(address.address.clone());
                        }
                    }
                    self.base.addresses_loaded = true;
                    let gap_limit = if self.should_use_reduced_gap_limit() { SequenceGapLimit::Initial.unused() } else { SequenceGapLimit::Initial.default() };
                    let _ = self.register_addresses_with_gap_limit(gap_limit, true);
                    let _ = self.register_addresses_with_gap_limit(gap_limit, false);
                },
                Err(err) => println!("Error loading derivation path entity with addresses")
            }
        }
    }

    fn reload_addresses(&mut self) {
        self.internal_addresses.clear();
        self.external_addresses.clear();
        self.base.used_addresses.clear();
        self.base.addresses_loaded = false;
        self.load_addresses();
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.base.standalone_extended_public_key_unique_id()
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::Funds
    }

    fn balance(&self) -> u64 {
        self.base.balance()
    }

    fn private_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        self.base.private_key_at_index_path(index_path)
    }

    fn public_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        self.base.public_key_at_index_path(index_path)
    }

    fn public_key_data_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<Vec<u8>> {
        self.base.public_key_data_at_index_path(index_path)
    }

    fn base_index_path<T>(&self) -> IndexPath<T> {
        self.base.base_index_path()
    }

    fn index_path_for_known_address(&self, address: Option<String>) -> Option<IndexPath<u32>> {
        if let Some(address) = address {
            if let Some(pos) = self.internal_addresses.iter().position(|addr| addr == &address) {
                return Some(IndexPath::index_path_with_indexes(vec![1, pos as u32]));
            } else if let Some(pos) = self.external_addresses.iter().position(|addr| addr == &address) {
                return Some(IndexPath::index_path_with_indexes(vec![0, pos as u32]));
            }
        }
        None

    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.base.generate_extended_public_key_from_seed(seed, wallet_unique_id)
    }

    fn context(&self) -> &ManagedContext {
        self.base.context()
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        // todo: avoid clone & optioning address
        if self.contains_address(Some(address.clone())) {
            if !self.used_addresses.contains(address) {
                self.used_addresses.push(address.clone());
                if self.all_change_addresses().contains(address) {
                    let _ = self.register_addresses_with_gap_limit(SequenceGapLimit::Internal.default(), true);
                } else {
                    let _ = self.register_addresses_with_gap_limit(SequenceGapLimit::External.default(), false);
                }
            }
            true
        }
        false
    }

}

impl FundsDerivationPath {

    pub fn bip32_derivation_path_for_account_number(account_number: u32, chain: &Chain) -> Self {
        let indexes = vec![UInt256::from_u32(account_number).unwrap()];
        let hardened = vec![true];
        let r#type = DerivationPathType::ClearFunds;
        let signing_algorithm = KeyType::ECDSA;
        let reference = DerivationPathReference::BIP32;
        Self {
            base: DerivationPath::derivation_path_with_indexes(indexes, hardened, r#type, signing_algorithm, reference, chain),
            is_for_first_account: account_number == 0,
            ..Default::default()
        }
    }

    pub fn bip44_derivation_path_for_account_number(account_number: u32, chain: &Chain) -> Self {
        let coin_type = if chain.is_mainnet() { 5 } else { 1 };
        let indexes = vec![UInt256::from_u32(44).unwrap(), UInt256::from_u32(coin_type).unwrap(), UInt256::from_u32(account_number).unwrap()];
        let hardened = vec![true, true, true];
        let r#type = DerivationPathType::ClearFunds;
        let signing_algorithm = KeyType::ECDSA;
        let reference = DerivationPathReference::BIP44;
        Self {
            base: DerivationPath::derivation_path_with_indexes(indexes, hardened, r#type, signing_algorithm, reference, chain),
            is_for_first_account: account_number == 0,
            ..Default::default()
        }
    }

    pub fn should_use_reduced_gap_limit(&mut self) -> bool {
        if !self.checked_initial_has_known_balance {
            if let Ok(has_known_balance) = Keychain::get_int(self.has_known_balance_unique_id_string()) {
                self.has_known_balance_internal = has_known_balance != 0;
                self.checked_initial_has_known_balance = true;
            }
        }
        !self.has_known_balance_internal &&
            !(self.is_for_first_account && self.reference() == DerivationPathReference::BIP44)
    }

    pub fn set_has_known_balance(&mut self) {
        if !self.has_known_balance_internal {
            Keychain::set_int(1, self.has_known_balance_unique_id_string(), false)
                .expect("Can't save balance flag in keychain");
            self.has_known_balance_internal = true;
        }
    }


    fn has_known_balance_unique_id_string(&self) -> String {
        format!("{}_{}_{}", DERIVATION_PATH_IS_USED_KEY, self.base.account.unwrap().unique_id(), self.reference().into())
    }

    /// Wallets are composed of chains of addresses. Each chain is traversed until a gap of a certain number of addresses is
    /// found that haven't been used in any transactions. This method returns an array of <gapLimit> unused addresses
    /// following the last used address in the chain. The internal chain is used for change addresses and the external chain
    /// for receive addresses.
    pub fn register_addresses_with_gap_limit(&mut self, gap_limit: u32, internal: bool) -> Result<HashSet<String>, util::Error> {
        // todo: check
        let wallet = self.base.account.unwrap().wallet.unwrap();

        if !wallet.is_transient {
            assert!(self.base.addresses_loaded, "addresses must be loaded before calling this function");
        }
        let mut arr = if internal { self.internal_addresses.clone() } else { self.external_addresses.clone() };
        //NSMutableArray *a = [NSMutableArray arrayWithArray:(internal) ? self.internalAddresses : self.externalAddresses];
        let mut i = arr.len();
        let used_addresses_contains_last_from_array = |set: &HashSet<String>| {
            if let Some(last) = set.iter().last() {
                self.used_addresses().contains(last)
            } else {
                false
            }
        };
        // keep only the trailing contiguous block of addresses with no transactions
        while i > 0 && !used_addresses_contains_last_from_array(&arr) {
            i -= 1;
        }

        if i > 0 {
            arr.iter().take(i).for_each(|addr| {
                arr.remove(addr);
            });
        }
        if arr.len() >= gapLimit {
            return Ok(arr.iter().take(gap_limit as usize).collect());
        }

        if gap_limit > 1 { // get receiveAddress and changeAddress first to avoid blocking
            self.receive_address();
            self.change_address();
        }

        // It seems weird to repeat this, but it's correct because of the original call receive address and change address
        arr = if internal { self.internal_addresses.clone() } else { self.external_addresses.clone() };
        i = arr.len();

        let mut n = i as u32;

        // keep only the trailing contiguous block of addresses with no transactions
        while i > 0 && !used_addresses_contains_last_from_array(&arr) {
            i -= 1;
        }
        if i > 0 {
            arr.iter().take(i).for_each(|addr| {
                arr.remove(addr);
            });
        }
        if arr.len() >= gapLimit {
            return Ok(arr.iter().take(gap_limit as usize).collect());
        }

        let mut add_addresses = HashMap::<u32, String>::new();

        let get_address = |n: u32, internal: bool| {
            if let Some(pub_key) = self.public_key_data_at_index(n, internal) {
                let key = ECDSAKey::key_with_public_key_data(&pub_key);
                if let Some(addr) = address_with_public_key_data(key.public_key_data(), self.base.chain) {
                    return Some(addr);
                }
            }
            None
        };
        while a.len() < gap_limit { // generate new addresses up to gapLimit
            if let Some(addr) = get_address(n, internal) {
                self.base.all_addresses.push(addr);
                if internal {
                    self.internal_addresses.insert(addr.clone());
                } else {
                    self.external_addresses.insert(addr.clone());
                }
                arr.insert(addr.clone());
                add_addresses.insert(n, addr.clone());
                n += 1;
            } else {
                println!("error generating keys");
                return Err(util::Error::DefaultWithCode(&format!("Error generating public keys"), 500));
            }
        }

        if !wallet.is_transient {
            match DerivationPathEntity::derivation_path_entity_matching_derivation_path(self, self.context()) {
                Ok(derivationPathEntity) => {
                    for (n, addr) in add_addresses {
                        match AddressEntity::create_with(
                            derivationPathEntity.id,
                            addr.as_str(),
                            n as i32,
                            internal,
                            false,
                            self.context()
                        ) {
                            Ok(created) => {},
                            Err(err) => { return Err(util::Error::Default(&format!("Can't retrieve derivation path"))); }
                        }
                    }
                },
                Err(err) => {
                    return Err(util::Error::Default(&format!("Can't retrieve derivation path")));
                }
            }
        }
        Ok(arr)
    }

    pub fn addresses_for_export_with_internal_range<R: RangeBounds<usize>>(&self, internal_range: R, external_range: R) -> Vec<String> {
        let mut addresses = Vec::<String>::new();
        for i in internal_range {
            if let Some(pub_key) = self.public_key_data_at_index(i as u32, true) {
                let key = ECDSAKey::key_with_public_key_data(&pub_key);
                if let Some(addr) = address_with_public_key_data(key.public_key_data(), self.base.chain) {
                    addresses.push(addr);
                }
            }
        }
        for i in external_range {
            if let Some(pub_key) = self.public_key_data_at_index(i as u32, false) {
                let key = ECDSAKey::key_with_public_key_data(&pub_key);
                if let Some(addr) = address_with_public_key_data(key.public_key_data(), self.base.chain) {
                    addresses.push(addr);
                }
            }
        }
        addresses
    }

    /// gets an address at an index path
    pub fn address_at_index(&self, index: u32, internal: bool) -> Option<String> {
        if let Some(pub_key) = self.public_key_data_at_index(index, internal) {
            let key = ECDSAKey::key_with_public_key_data(&pub_key);
            address_with_public_key_data(key.public_key_data(), self.base.chain)
        } else {
            None
        }
    }

    // returns the first unused external address
    pub fn receive_address(&mut self) -> Option<&String> {
        // TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        self.receive_address_at_offset(0)
    }

    pub fn receive_address_at_offset(&mut self, offset: u32) -> Option<&String> {
        // TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        if let Ok(addresses) = &self.register_addresses_with_gap_limit(offset + 1, false) {
            if let Some(addr) = addresses.iter().last() {
                return Some(addr);
            }
        }
        self.all_receive_addresses().iter().last()
    }

    // returns the first unused internal address
    pub fn change_address(&mut self) -> Option<&String> {
        // TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        if let Ok(addresses) = &self.register_addresses_with_gap_limit(1, true) {
            return addresses.iter().last();
        }
        None
    }

    /// all previously generated external addresses
    pub fn all_receive_addresses(&self) -> HashSet<String> {
        self.external_addresses.clone()
    }

    /// all previously generated internal addresses
    pub fn all_change_addresses(&self) -> HashSet<String> {
        self.internal_addresses.clone()
    }

    /// true if the address is controlled by the wallet
    pub fn contains_change_address(&self, address: Option<String>) -> bool {
        address.is_some() && self.internal_addresses.contains(&address.unwrap())
    }

    /// true if the address is controlled by the wallet
    pub fn contains_receive_address(&self, address: Option<String>) -> bool {
        address.is_some() && self.external_addresses.contains(&address.unwrap())
    }

    pub fn used_receive_addresses(&self) -> Vec<String> {
        self.all_receive_addresses().intersection(&self.used_addresses()).collect()
    }

    pub fn used_change_addresses(&self) -> Vec<String> {
        self.all_change_addresses().intersection(&self.used_addresses()).collect()
    }

    pub fn public_key_data_at_index(&self, n: u32, internal: bool) -> Option<Vec<u8>> {
        self.public_key_data_at_index_path(&IndexPath::index_path_with_indexes(vec![if internal { 1 } else { 0 }, n]))
    }

    pub fn private_key_string_at_index(&self, index: u32, internal: bool, seed: Option<Vec<u8>>) -> Option<&String> {
        self.serialized_private_keys(vec![index], internal, seed)
            .and_then(|keys| keys.last())
    }

    pub fn private_keys(&self, indexes: Vec<u32>, internal: bool, seed: Option<Vec<u8>>) -> Vec<&dyn IKey> {
        self.base.private_keys_at_index_paths(
            indexes.iter()
                .map(|&index|
                    IndexPath::index_path_with_indexes(vec![if internal { 1 } else { 0 }, index]))
                .collect(),
            seed)
    }

    pub fn serialized_private_keys(&self, indexes: Vec<u32>, internal: bool, seed: Option<Vec<u8>>) -> Option<Vec<String>> {
        self.base.serialized_private_keys_at_index_paths(
            indexes.iter()
                .map(|&index|
                    IndexPath::index_path_with_indexes(vec![if internal { 1 } else { 0 }, index])).collect(), seed)
    }

}
