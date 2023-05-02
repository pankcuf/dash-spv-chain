use std::collections::{HashMap, HashSet};
use std::ops::RangeBounds;
use crate::chain::chain::Chain;
use crate::chain::ext::settings::Settings;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::UInt256;
use crate::derivation::derivation_path::{DerivationPath, IDerivationPath};
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::derivation::sequence_gap_limit::SequenceGapLimit;
use crate::keychain::keychain::Keychain;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::util;
use crate::util::address::Address;

const DERIVATION_PATH_IS_USED_KEY: &str = "DERIVATION_PATH_IS_USED_KEY";

pub trait IFundsDerivationPath {
    /// all previously generated external addresses
    fn all_receive_addresses(&self) -> Vec<String>;
}

#[derive(Debug, Default, PartialEq)]
pub struct FundsDerivationPath {
    pub base: DerivationPath,

    internal_addresses: HashSet<String>,
    external_addresses: HashSet<String>,

    is_for_first_account: bool,
    has_known_balance_internal: bool,
    checked_initial_has_known_balance: bool,
}

impl IDerivationPath for FundsDerivationPath {
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
            match DerivationPathEntity::derivation_path_entity_matching_derivation_path_with_addresses(self, self.context()) {
                Ok((entity, addresses, used_in_inputs, used_in_outputs)) => {
                    self.base.sync_block_height = entity.sync_block_height as u32;
                    for address_entity in addresses {
                        let mut a = Vec::from_iter(if address_entity.internal.0 { self.internal_addresses.iter() } else { self.external_addresses.iter() });
                        let a_index = address_entity.index as usize;
                        // todo: check if a is needed
                        // while a_index >= a.len() {
                        //     a.push(&String::new());
                        // }
                        if !Address::is_valid_dash_address_for_script_map(&address_entity.address, self.base.account.unwrap().wallet.unwrap().chain.script()) {
                            continue;
                        }
                        let address = address_entity.address;
                        a.push(&address);
                        // a[a_index] = &address;
                        if !used_in_inputs.is_empty() || !used_in_outputs.is_empty() {
                            self.base.used_addresses.push(address.clone());
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

    fn string_representation(&mut self) -> &str {
        self.base.string_representation()
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

    fn set_balance(&mut self, amount: u64) {
        self.base.set_balance(amount)
    }

    fn private_key_at_index_path_from_seed<KEY: IKey>(&self, index_path: &IndexPath<u32>, seed: &Vec<u8>) -> Option<KEY> where Self: Sized {
        self.base.private_key_at_index_path_from_seed(index_path, seed)
    }

    fn index_path_for_known_address(&self, address: &String) -> Option<IndexPath<u32>> {
        self.internal_addresses.iter().position(|addr| addr == address)
            .map(|pos| IndexPath::index_path_with_indexes(vec![1, pos as u32]))
            .or(self.external_addresses.iter().position(|addr| addr == address)
                .map(|pos| IndexPath::index_path_with_indexes(vec![0, pos as u32])))
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.base.generate_extended_public_key_from_seed(seed, wallet_unique_id)
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        // todo: avoid clone & optioning address
        let contains = self.contains_address(address);
        if contains {
            if !self.used_addresses().contains(address) {
                self.used_addresses().insert(address.clone());
                if self.all_change_addresses().contains(address) {
                    self.register_addresses_with_gap_limit(SequenceGapLimit::Internal.default(), true)
                        .expect("Error register_addresses_with_gap_limit");
                } else {
                    self.register_addresses_with_gap_limit(SequenceGapLimit::External.default(), false)
                        .expect("Error register_addresses_with_gap_limit");
                }
            }
        }
        contains
    }

    fn register_addresses(&mut self) -> HashSet<String> {
        let _ = self.register_addresses_with_gap_limit(SequenceGapLimit::Initial.default(), false);
        let _ = self.register_addresses_with_gap_limit(SequenceGapLimit::Initial.default(), true);
        let mut addresses: HashSet<String> = HashSet::new();
        addresses.extend(self.all_receive_addresses());
        addresses.extend(self.all_change_addresses());
        addresses
    }
}

impl FundsDerivationPath {

    pub fn bip32_derivation_path_for_account_number(account_number: u32, chain: &Chain) -> Self {
        let indexes = vec![UInt256::from(account_number)];
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
        let indexes = vec![
            UInt256::from(44u32),
            UInt256::from(chain.r#type().coin_type()),
            UInt256::from(account_number)
        ];
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
            !(self.is_for_first_account && DerivationPathReference::BIP44.eq(self.reference()))
    }

    pub fn set_has_known_balance(&mut self) {
        if !self.has_known_balance_internal {
            Keychain::set_int(1, self.has_known_balance_unique_id_string(), false)
                .expect("Can't save balance flag in keychain");
            self.has_known_balance_internal = true;
        }
    }


    fn has_known_balance_unique_id_string(&self) -> String {
        let reference: u32 = self.reference().clone().into();
        format!("{}_{}_{}", DERIVATION_PATH_IS_USED_KEY, self.base.account.unwrap().unique_id(), reference)
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
        let limit = gap_limit as usize;
        if arr.len() >= limit {
            return Ok(arr.iter().take(limit).cloned().collect());
        }

        if limit > 1 { // get receiveAddress and changeAddress first to avoid blocking
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
        if arr.len() >= limit {
            return Ok(arr.iter().take(limit).cloned().collect());
        }

        let mut add_addresses = HashMap::<u32, String>::new();

        let get_address = |n: u32, internal: bool|
            self.public_key_data_at_index(n, internal)
                .map(|pub_key| ECDSAKey::key_with_public_key_data(&pub_key))
                .map(|mut key| Address::with_public_key_data(&key.public_key_data(), self.base.chain.script()));
        while arr.len() < limit { // generate new addresses up to gapLimit
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
                return Err(util::Error::DefaultWithCode(format!("Error generating public keys"), 500));
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
                            Err(err) => { return Err(util::Error::Default(format!("Can't retrieve derivation path"))); }
                        }
                    }
                },
                Err(err) => {
                    return Err(util::Error::Default(format!("Can't retrieve derivation path")));
                }
            }
        }
        Ok(arr)
    }

    // pub fn addresses_for_export_with_internal_range<R: RangeBounds<usize> + Iterator>(&mut self, internal_range: R, external_range: R) -> Vec<String> {
    //     let mut addresses = Vec::<String>::new();
    //     internal_range.for_each(|i| {
    //
    //     });
    //     for i in internal_range {
    //         if let Some(pub_key) = self.public_key_data_at_index(i as u32, true) {
    //             if let Some(mut key) = ECDSAKey::key_with_public_key_data(&pub_key) {
    //                 addresses.push(Address::with_public_key_data(&key.public_key_data(), &self.base.chain.params.script_map));
    //             }
    //         }
    //     }
    //     for i in external_range {
    //         if let Some(pub_key) = self.public_key_data_at_index(i as u32, false) {
    //             if let Some(mut key) = ECDSAKey::key_with_public_key_data(&pub_key) {
    //                 addresses.push(Address::with_public_key_data(&key.public_key_data(), &self.base.chain.params.script_map));
    //             }
    //         }
    //     }
    //     addresses
    // }

    /// gets an address at an index path
    pub fn address_at_index(&mut self, index: u32, internal: bool) -> Option<String> {
        self.public_key_data_at_index(index, internal)
            .and_then(|pub_key| ECDSAKey::key_with_public_key_data(&pub_key)
                .map(|mut key| Address::with_public_key_data(&key.public_key_data(), self.base.chain.script())))
    }

    // returns the first unused external address
    pub fn receive_address(&mut self) -> Option<&String> {
        // TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        self.receive_address_at_offset(0)
    }

    pub fn receive_address_at_offset(&mut self, offset: u32) -> Option<&String> {
        // TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        self.register_addresses_with_gap_limit(offset + 1, false)
            .ok()
            .and_then(|addresses| addresses.iter().last())
            .or(self.all_receive_addresses().iter().last())
        // if let Ok(addresses) = &self.register_addresses_with_gap_limit(offset + 1, false) {
        //     if let Some(addr) = addresses.iter().last() {
        //         return Some(addr);
        //     }
        // }
        // self.all_receive_addresses().iter().last()
    }

    // returns the first unused internal address
    pub fn change_address(&mut self) -> Option<&String> {
        // TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        self.register_addresses_with_gap_limit(1, true)
            .ok()
            .and_then(|addresses| addresses.iter().last())
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
    pub fn contains_change_address(&self, address: &String) -> bool {
        self.internal_addresses.contains(address)
    }

    /// true if the address is controlled by the wallet
    pub fn contains_receive_address(&self, address: &String) -> bool {
        self.external_addresses.contains(address)
    }

    pub fn used_receive_addresses(&self) -> Vec<String> {
        self.all_receive_addresses().intersection(&self.used_addresses()).map(|&a| a).collect()
    }

    pub fn used_change_addresses(&self) -> Vec<String> {
        self.all_change_addresses().intersection(&self.used_addresses()).map(|&a| a).collect()
    }

    pub fn public_key_data_at_index(&mut self, n: u32, internal: bool) -> Option<Vec<u8>> {
        self.public_key_data_at_index_path(&IndexPath::index_path_with_indexes(vec![if internal { 1 } else { 0 }, n]))
    }

    pub fn private_key_string_at_index(&self, index: u32, internal: bool, seed: Option<Vec<u8>>) -> Option<&String> {
        self.serialized_private_keys(vec![index], internal, seed)
            .and_then(|keys| keys.last())
    }

    pub fn private_keys<KEY: IKey>(&self, indexes: Vec<u32>, internal: bool, seed: &Vec<u8>) -> Vec<KEY> {
        self.private_keys_at_index_paths(
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
