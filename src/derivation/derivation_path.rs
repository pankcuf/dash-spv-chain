use std::collections::HashSet;
use std::fmt::Debug;
use byte::BytesExt;
use hashes::{Hash, sha256};
use hashes::hex::ToHex;
use serde_json::json;
use crate::chain::bip::bip32;
use crate::crypto::{ECPoint, UInt256, UInt512};
use crate::chain::chain::Chain;
use crate::derivation::derivation_path_feature_purpose::DerivationPathFeaturePurpose;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::index_path::{IIndexPath, IndexHardSoft, IndexPath};
use crate::derivation::uint256_index_path::UInt256IndexPath;
use crate::keychain::keychain::{Keychain, KeychainDictValueKind};
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::wallet::Wallet;
use crate::storage::manager::managed_context::ManagedContext;
use crate::{derivation, util};
use crate::chain::bip::bip32::StringKey;
use crate::chain::bip::dip14::ckd_priv_256;
use crate::chain::ext::settings::Settings;
use crate::crypto::byte_util::{AsBytes, clone_into_array};
use crate::derivation::{DERIVATION_PATH_EXTENDED_PUBLIC_KEY_STANDALONE_BASED_LOCATION, DERIVATION_PATH_EXTENDED_PUBLIC_KEY_WALLET_BASED_LOCATION, DERIVATION_PATH_EXTENDED_SECRET_KEY_WALLET_BASED_LOCATION, DERIVATION_PATH_STANDALONE_INFO_DEPTH, DERIVATION_PATH_STANDALONE_INFO_DICTIONARY_LOCATION, DERIVATION_PATH_STANDALONE_INFO_TERMINAL_HARDENED, DERIVATION_PATH_STANDALONE_INFO_TERMINAL_INDEX};
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::platform::identity::identity::Identity;
use crate::storage::models::account::user::UserEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::util::address::Address;
use crate::util::data_ops::short_hex_string_from;

pub trait IDerivationPath<IPATH: IIndexPath = UInt256IndexPath>: Send + Sync + Debug {
    fn chain(&self) -> &Chain;
    fn wallet(&self) -> Option<&Wallet>;
    fn context(&self) -> &ManagedContext;
    fn signing_algorithm(&self) -> KeyType;
    fn reference(&self) -> &DerivationPathReference;
    fn extended_public_key(&mut self) -> Option<&dyn IKey>;
    fn extended_public_key_data(&mut self) -> Option<Vec<u8>> {
        self.extended_public_key().and_then(|mut key| key.extended_public_key_data())
    }
    fn has_extended_public_key(&self) -> bool;
    fn is_derivation_path_equal(&self, other: &dyn IDerivationPath<UInt256IndexPath>) -> bool {
        todo!()
        // *self == other
    }

    /// all previously generated addresses
    fn all_addresses(&self) -> HashSet<String>;
    /// all previously used addresses
    fn used_addresses(&self) -> HashSet<String>;
    /// true if the address is controlled by the wallet
    fn contains_address(&self, address: &String) -> bool {
        self.all_addresses().contains(address)
    }
    // gets an address at an index path
    fn address_at_index_path(&mut self, index_path: &IndexPath<u32>) -> Option<String> {
        self.public_key_data_at_index_path(index_path)
            .map(|data| Address::with_public_key_data(&data, self.chain().script()))
    }
    // true if the address was previously used as an input or output in any wallet transaction
    fn address_is_used(&self, address: &String) -> bool {
        self.used_addresses().contains(address)
    }
    // true if the address at index path was previously used as an input or output in any wallet transaction
    fn address_is_used_at_index_path(&mut self, index_path: &IndexPath<u32>) -> bool {
        self.address_at_index_path(index_path)
            .map_or(false, |address| self.address_is_used(&address))
    }

    fn load_addresses(&mut self) {}
    fn reload_addresses(&mut self) {}
    // this returns the derivation path's visual representation (e.g. m/44'/5'/0')
    fn string_representation(&mut self) -> &str;
    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String>;
    fn kind(&self) -> DerivationPathKind;
    fn balance(&self) -> u64;
    fn set_balance(&mut self, amount: u64);
    /// gets a private key at an index
    fn private_key_at_index<KEY: IKey>(&self, index: u32, seed: &Vec<u8>) -> Option<KEY> where Self: Sized {
        self.private_key_at_index_path_from_seed(&IndexPath::index_path_with_index(index), seed)
    }
    // fn is_derivation_path_equal(&self, other: &dyn IDerivationPath<IPATH>) -> bool {

    // fn private_key_at_index_path_from_seed<KEY: IKey>(&self, index_path: &IndexPath<u32>, seed: &Vec<u8>) -> Option<KEY> where Self: Sized + IDerivationPath<IPATH> {
    fn private_key_at_index_path_from_seed<KEY: IKey>(&self, index_path: &IndexPath<u32>, seed: &Vec<u8>) -> Option<KEY> where Self: Sized;
    fn private_key_for_known_address<KEY: IKey>(&self, address: &String, seed: &Vec<u8>) -> Option<KEY> where Self: Sized {
        self.index_path_for_known_address(address)
            .and_then(|index_path| self.private_key_at_index_path_from_seed(&index_path, seed))
    }

    fn private_keys_at_index_paths<KEY: IKey>(&self, index_paths: Vec<IndexPath<u32>>, seed: &Vec<u8>) -> Vec<KEY> where Self: Sized {
        self.signing_algorithm().private_keys_at_index_paths(index_paths, seed)
    }

    fn public_key_at_index_path(&mut self, index_path: &IndexPath<u32>) -> Option<Box<dyn IKey>> /*where Self: Sized*/ {
        self.public_key_data_at_index_path(index_path)
            .and_then(|data| self.signing_algorithm().key_with_public_key_data(&data))
    }

    fn public_key_data_at_index_path(&mut self, index_path: &IndexPath<u32>) -> Option<Vec<u8>> {
        self.extended_public_key_data()
            .and_then(|data| self.signing_algorithm().public_key_from_extended_public_key_data(&data, index_path))
    }
    // fn base_index_path(&self) -> IndexPath<u32> {
    //     IndexPath::index_path_with_indexes(
    //         (0..self.indexes().len())
    //             .into_iter()
    //             .map(|position| self.index_u64_at_position(position) as u32)
    //             .collect())
    // }

    fn index_path_for_known_address(&self, address: &String) -> Option<IndexPath<u32>>;
    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey>;

    fn register_transaction_address(&mut self, address: &String) -> bool;
    fn register_addresses_with_gap_limit(&mut self, gap_limit: u32) -> Result<Vec<String>, util::Error> {
        Err(util::Error::Default(format!("Should be overriden")))
    }

    fn register_addresses(&mut self) -> HashSet<String> {
        HashSet::new()
    }

    fn create_identifier_for_derivation_path(&mut self) -> String {
        short_hex_string_from(&sha256::Hash::hash(&self.extended_public_key_data().unwrap_or(vec![])).into_inner())
    }


    fn standalone_extended_public_key_location_string(&mut self) -> Option<String> {
        self.standalone_extended_public_key_unique_id()
            .map(|unique_id| derivation::standalone_extended_public_key_location_string_for_unique_id(&unique_id))
    }

    fn standalone_info_dictionary_location_string(&mut self) -> Option<String> {
        self.standalone_extended_public_key_unique_id()
            .map(|unique_id| derivation::standalone_info_dictionary_location_string_for_unique_id(&unique_id))
    }

    fn wallet_based_extended_public_key_location_string_for_wallet_unique_id(&self, unique_id: &String) -> String where Self: IIndexPath {
        format!("{}{}{}",
                derivation::wallet_based_extended_public_key_location_string_for_unique_id(unique_id),
                self.signing_algorithm().derivation_string(),
                self.index_path_enumerated_string()
        )
    }

    /// Storage

    fn store_extended_public_key_under_wallet_unique_id(&mut self, wallet_unique_id: &String) -> bool where Self: IIndexPath {
        if let Some(mut key) = self.extended_public_key() {
            Keychain::set_data(self.wallet_based_extended_public_key_location_string_for_wallet_unique_id(wallet_unique_id), key.extended_public_key_data(), false)
                .expect("Can't store extended public key")
        } else {
            false
        }
    }

    fn load_identities(&self, address: &String) -> (Option<&Identity>, Option<&Identity>) {
        (None, None)
    }
}

#[derive(Clone, Debug, Default)]
pub struct DerivationPath {
    pub base: UInt256IndexPath,
    pub hardened_indexes: Vec<bool>,
    /// is this an open account
    pub r#type: DerivationPathType,
    pub signing_algorithm: KeyType,
    /// account for the derivation path
    pub chain: &'static Chain,
    /// account for the derivation path
    pub account: Option<&'static Account>,
    pub wallet: Option<&'static Wallet>,
    /// extended Public Key
    pub extended_public_key_data: Vec<u8>,
    /// extended Public Key Identifier, which is just the short hex string of the extended public key
    pub standalone_extended_public_key_unique_id: Option<String>,
    /// the wallet_based_extended_public_key_location_string is the key used to store the public key in the key chain
    pub wallet_based_extended_public_key_location_string: Option<String>,
    /// the wallet_based_extended_public_key_location_string is the key used to store the private key in the key chain,
    /// this is only available on authentication derivation paths
    pub wallet_based_extended_private_key_location_string: Option<String>,
    /// current derivation path balance excluding transactions known to be invalid
    pub balance: u64,
    /// purpose of the derivation path if BIP 43 based
    pub purpose: u64,
    /// currently the derivationPath is synced to this block height
    pub sync_block_height: u32,

    /// the reference of type of derivation path
    pub reference: DerivationPathReference,
    /// there might be times where the derivationPath is actually unknown, for example when importing from an extended public key
    pub derivation_path_is_known: bool,

    pub(crate) addresses_loaded: bool,

    pub(crate) all_addresses: Vec<String>,
    pub(crate) used_addresses: Vec<String>,

    //master public key used to generate wallet addresses
    extended_public_key: Option<&'static dyn IKey>,

    pub standalone_extended_public_key_location_string: Option<String>,

    pub context: &'static ManagedContext,
    // @property (nonatomic, readonly) DSDerivationPathEntity *derivationPathEntity;

    /// private
    pub(crate) depth: u8,
    pub(crate) string_representation: Option<String>,
}

impl IIndexPath for DerivationPath {
    type Item = UInt256;

    fn new(indexes: Vec<Self::Item>) -> Self {
        Self { base: UInt256IndexPath { indexes, ..Default::default() }, ..Default::default() }
    }

    fn indexes(&self) -> &Vec<Self::Item> {
        &self.base.indexes
    }

    fn hardened_indexes(&self) -> &Vec<bool> {
        &self.base.hardened_indexes
    }
}

impl PartialEq for DerivationPath {
    fn eq(&self, other: &Self) -> bool {
        self.standalone_extended_public_key_unique_id.eq(&other.standalone_extended_public_key_unique_id)
        // self.standalone_extended_public_key_unique_id()
        // todo!()
        //return [self.standaloneExtendedPublicKeyUniqueID isEqualToString:((DSDerivationPath *)object).standaloneExtendedPublicKeyUniqueID];
    }
}

impl IDerivationPath<UInt256IndexPath> for DerivationPath {
    // type Item = UInt256IndexPath;

    fn chain(&self) -> &Chain {
        &self.chain
    }

    fn wallet(&self) -> Option<&Wallet> {
        if self.wallet.is_some() {
            return self.wallet;
        }
        if let Some(account) = &self.account {
            if account.wallet.is_some() {
                return account.wallet;
            }
        }
        None
    }

    fn context(&self) -> &ManagedContext {
        self.context
    }

    fn signing_algorithm(&self) -> KeyType {
        self.signing_algorithm
    }

    fn reference(&self) -> &DerivationPathReference {
        &self.reference
    }

    fn extended_public_key(&mut self) -> Option<&dyn IKey> {
        self.extended_public_key.or({
            let key_path = if self.wallet.is_some() && (!self.is_empty() || self.reference == DerivationPathReference::Root) {
                self.wallet_based_extended_public_key_location_string()
            } else {
                self.standalone_extended_public_key_location_string().unwrap()
            };
            Keychain::get_data(key_path).ok().and_then(|data| {
                self.extended_public_key = self.signing_algorithm.key_with_extended_public_key_data(&data);
                self.extended_public_key
            })
        })
    }


    fn has_extended_public_key(&self) -> bool {
        self.extended_public_key.is_some() || Keychain::has_data(if self.wallet.is_some() && (!self.is_empty() || self.reference == DerivationPathReference::Root) {
            self.wallet_based_extended_public_key_location_string.unwrap()
        } else {
            self.standalone_extended_public_key_location_string.unwrap()
        }).unwrap_or(false)
    }

    fn all_addresses(&self) -> HashSet<String> {
        HashSet::from_iter(self.all_addresses.into_iter())
    }

    fn used_addresses(&self) -> HashSet<String> {
        HashSet::from_iter(self.used_addresses.into_iter())
    }

    fn string_representation(&mut self) -> &str {
        if let Some(rep) = &self.string_representation {
            return rep.as_str()
        }
        let mut mutable_string = "m".to_string();
        if self.length() > 0 {
            self.base.indexes.iter().zip(&self.hardened_indexes).for_each(|(index, &hardened)| {
                mutable_string += &derivation::string_representation_of_derivation_path_index(index, hardened, Some(self.context));
            });
        } else if self.depth != 0 {
            for i in 0..self.depth - 1 {
                mutable_string += "/?'";
            }
            mutable_string += &derivation::string_representation_of_derivation_path_index(self.base.indexes().last().unwrap_or(&UInt256::MIN), self.terminal_hardened(), Some(self.context));
        }
        self.string_representation = Some(mutable_string.clone());
        mutable_string.as_str()
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.standalone_extended_public_key_unique_id.or({
            if self.extended_public_key.is_none() && self.wallet.is_none() {
                assert!(false, "we really should have a wallet");
                None
            } else {
                let id = Some(self.create_identifier_for_derivation_path());
                self.standalone_extended_public_key_unique_id = id.clone();
                id
            }
        })
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::Default
    }
    fn balance(&self) -> u64 {
        self.balance
    }

    fn set_balance(&mut self, amount: u64) {
        self.balance = amount;
    }

    fn private_key_at_index_path_from_seed<KEY: IKey>(&self, index_path: &IndexPath<u32>, seed: &Vec<u8>) -> Option<KEY> where Self: Sized {
        if self.is_empty() {
            None
        } else {
            self.signing_algorithm().private_key_at_index_path_from_seed(index_path, seed)
        }
    }

    fn index_path_for_known_address(&self, address: &String) -> Option<IndexPath<u32>> {
        assert!(false, "This must be implemented in subclasses");
        None
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.generate_extended_public_key_from_seed_and_store_private_key(seed, wallet_unique_id, false)
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        // todo: avoid clone & optioning address
        let has_addr = self.contains_address(address);
        if has_addr && !self.used_addresses.contains(address) {
            self.used_addresses.push(address.clone());
        }
        has_addr
    }

}

impl DerivationPath {

    pub fn master_blockchain_identity_contacts_derivation_path_for_account_number(account_number: u32, chain: &Chain) -> Self {
        Self::derivation_path_with_indexes(
            vec![
                DerivationPathFeaturePurpose::Default.into_u256(),
                UInt256::from(chain.r#type().coin_type()),
                DerivationPathFeaturePurpose::DashPay.into_u256(),
                UInt256::from(account_number),
            ],
            vec![true, true, true, true],
            DerivationPathType::PartialPath,
            KeyType::ECDSA,
            DerivationPathReference::ContactBasedFundsRoot,
            chain)
    }

    pub fn derivation_path_with_indexes(indexes: Vec<UInt256>, hardened: Vec<bool>, r#type: DerivationPathType, signing_algorithm: KeyType, reference: DerivationPathReference, chain: &Chain) -> Self {
        Self {
            base: UInt256IndexPath { indexes, hardened_indexes: hardened },
            r#type,
            signing_algorithm,
            chain,
            reference,
            context: chain.chain_context(),
            ..Default::default()
        }
    }

    pub fn derivation_path_with_serialized_extended_public_key(key: &String, chain: &Chain) -> Option<Self> {
        let key_type = KeyType::ECDSA;
        derivation::deserialized_extended_public_key_for_chain(key, &chain.params).map(|pk| {
            let mut path = Self::derivation_path_with_indexes(
                vec![pk.child],
                vec![pk.hardened],
                DerivationPathType::ViewOnlyFunds,
                key_type,
                DerivationPathReference::Unknown,
                chain
            );
            path.extended_public_key = key_type.key_with_extended_public_key_data(&pk.to_data());
            path.depth = pk.depth;
            path.standalone_save_extended_public_key_to_keychain();
            path.load_addresses();
            path
        }).ok()
    }

    pub fn init_with_extended_public_key_identifier(extended_public_key_identifier: String, chain: &Chain) -> Option<Self> {
        let key = derivation::standalone_info_dictionary_location_string_for_unique_id(&extended_public_key_identifier);
        return if let Ok(info_dictionary) = Keychain::get_dict::<String, KeychainDictValueKind>(key) {
            let terminal_index =
                if let Some(&KeychainDictValueKind::Uint256(terminal_index)) = info_dictionary.get(DERIVATION_PATH_STANDALONE_INFO_TERMINAL_INDEX) {
                    Some(terminal_index)
                } else {
                    None
                };

            let terminal_hardened = if let Some(&KeychainDictValueKind::Bool(terminal_hardened)) = info_dictionary.get(DERIVATION_PATH_STANDALONE_INFO_TERMINAL_HARDENED) {
                Some(terminal_hardened)
            } else {
                None
            };
            if terminal_index.is_none() || terminal_hardened.is_none() {
                return None;
            }
            // TODO: length here is zero! so is not based on indexes length?
            let key_type = KeyType::ECDSA;
            let mut s = Self {
                base: UInt256IndexPath { indexes: vec![terminal_index.unwrap()], hardened_indexes: vec![terminal_hardened.unwrap()] },
                r#type: DerivationPathType::ViewOnlyFunds,
                signing_algorithm: key_type,
                reference: DerivationPathReference::Unknown,
                chain,
                ..Default::default()
            };
            if let Ok(data) = Keychain::get_data(derivation::standalone_extended_public_key_location_string_for_unique_id(&extended_public_key_identifier)) {
                s.extended_public_key = key_type.key_with_extended_public_key_data(&data);
                if let Some(&KeychainDictValueKind::Byte(depth)) = info_dictionary.get(DERIVATION_PATH_STANDALONE_INFO_DEPTH) {
                    s.depth = depth
                } else {
                    return None;
                };
                s.load_addresses();
                Some(s)
            } else {
                None
            }
        } else {
            None
        }
    }

    // pub fn derivation_path_entity(&self) -> DerivationPathEntity {
    //     DerivationPathEntity::der
    // }
    //
    // - (DSDerivationPathEntity *)derivationPathEntity {
    // return [DSDerivationPathEntity derivationPathEntityMatchingDerivationPath:self inContext:self.managedObjectContext];
    // }
    //
    // - (DSDerivationPathEntity *)derivationPathEntityInContext:(NSManagedObjectContext *)context {
    // return [DSDerivationPathEntity derivationPathEntityMatchingDerivationPath:self inContext:context];
    // }
    /// Key Generation
    pub fn generate_extended_public_key_from_seed_no_store(&mut self, seed: &Vec<u8>) -> Option<&dyn IKey> {
        if seed.is_empty() || (self.is_empty() && !DerivationPathReference::Root.eq(self.reference())) {
            None
        } else if let Some(seed_key) = self.signing_algorithm().key_with_seed_data(seed) {
            self.extended_public_key = seed_key.private_derive_to_256bit_derivation_path(self);
            assert!(self.extended_public_key.is_some(), "extendedPublicKey should be set");
            if let Some(mut extended_public_key) = &self.extended_public_key {
                extended_public_key.forget_private_key();
                Some(extended_public_key)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn generate_extended_public_key_from_seed_and_store_private_key(&mut self, seed: &Vec<u8>, wallet_unique_id: String, store_private_key: bool) -> Option<&dyn IKey> {
        if seed.is_empty() || (self.is_empty() && !DerivationPathReference::Root.eq(self.reference())) {
            None
        } else if let Some(seed_key) = self.signing_algorithm().key_with_seed_data(seed) {
            self.extended_public_key = seed_key.private_derive_to_256bit_derivation_path(self);
            assert!(self.extended_public_key.is_some(), "extendedPublicKey should be set");
            if let Some(mut extended_public_key) = &self.extended_public_key {
                Keychain::set_data(
                    self.wallet_based_extended_public_key_location_string_for_wallet_unique_id(unique_id),
                    extended_public_key.extended_public_key_data(),
                    false)
                    .expect("Can't store extended_public_key_data in keychain");
                if store_private_key {
                    Keychain::set_data(
                        derivation::wallet_based_extended_private_key_location_string_for_unique_id(unique_id),
                        extended_public_key.extended_private_key_data(),
                        true)
                        .expect("Can't store extended_private_key_data in keychain");
                }
                extended_public_key.forget_private_key();
                Some(extended_public_key)
            } else {
                None
            }
        } else {
            None
        }
    }
    pub fn generate_extended_public_key_from_parent_derivation_path<P>(&mut self, path: &mut P, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> where P: IDerivationPath + IIndexPath<Item = UInt256> {
        assert_eq!(path.signing_algorithm(), self.signing_algorithm(), "The signing algorithms must be the same");
        assert!(self.length() > path.length(), "length must be inferior to the parent derivation path length");
        assert!(path.has_extended_public_key(), "the parent derivation path must have an extended public key");
        if self.is_empty() ||
            self.length() < path.length() ||
            !path.has_extended_public_key() ||
            path.signing_algorithm() != self.signing_algorithm() {
            return None;
        }
        for i in 0..path.length() {
            let index = self.index_at_position(i);
            assert_eq!(path.index_at_position(i), index, "This derivation path must start with elements of the parent derivation path");
            if path.index_at_position(i) != self.index_at_position(i) {
                return None;
            }
        }
        self.extended_public_key = path.extended_public_key()
            .and_then(|mut ext_pk| ext_pk.public_derive_to_256bit_derivation_path_with_offset(self, path.length()));
        assert!(self.extended_public_key.is_some(), "extendedPublicKey should be set");
        if let Some(unique_id) = wallet_unique_id {
            Keychain::set_data(
                self.wallet_based_extended_public_key_location_string_for_wallet_unique_id(unique_id),
                self.extended_public_key.and_then(|mut key| key.extended_public_key_data()),
                false)
                .expect("Can't store extended public key");
        }
        self.extended_public_key
    }

    pub fn serialized_private_keys_at_index_paths(&self, index_paths: Vec<IndexPath<u32>>, seed: Option<Vec<u8>>) -> Option<Vec<String>> {
        if seed.is_none() {
            return None;
        }
        if index_paths.is_empty() {
            return Some(vec![]);
        }
        let top_key_opt = self.signing_algorithm().key_with_seed_data(&seed.unwrap());
        if top_key_opt.is_none() {
            return Some(vec![]);
        }
        let derivation_path_extended_key_opt = top_key_opt.unwrap().private_derive_to_256bit_derivation_path(self);
        if derivation_path_extended_key_opt.is_none() {
            return Some(vec![]);
        }
        let derivation_path_extended_key = derivation_path_extended_key_opt.unwrap();
        Some(index_paths.into_iter()
            .filter_map(|index_path| derivation_path_extended_key.private_derive_to_path(&index_path)
                .map(|key| key.serialized_private_key_for_chain(self.chain.script()))).collect())
    }

    pub fn deserialized_extended_private_key_for_chain(extended_private_key_string: &String, chain: &Chain) -> Option<Vec<u8>> {
        bip32::from(extended_private_key_string, &chain.params)
            .map(|key| key.to_data())
            .ok()
    }

    pub fn serialized_extended_private_key_from_seed(&self, seed: &Vec<u8>) -> Option<String> {
        //if (!seed) return nil;
        let i = UInt512::bip32_seed_key(seed);
        let secret_part = &i.0[..32];
        match secp256k1::SecretKey::from_slice(secret_part) {
            Err(err) => None,
            Ok(seckey) => {
                let mut secret = UInt256(clone_into_array(secret_part));
                let mut chain = UInt256(clone_into_array(&i.0[32..]));
                let mut fingerprint = 0u32;
                let mut index = UInt256::MIN;
                let mut hardened = false;
                if !self.is_empty() {
                    for i in 0..self.length() - 1 {
                        ckd_priv_256(secret, chain, &self.index_at_position(i), self.hardened_at_position(i));
                    }
                    if let Some(mut key) = ECDSAKey::init_with_secret(secret, true) {
                        fingerprint = key.hash160().u32_le();
                        index = self.index_at_position(self.length() - 1);
                        hardened = self.hardened_at_position(self.length() - 1);
                        // account 0H
                        ckd_priv_256(secret, chain, &index, hardened);
                    }
                }
                let key = bip32::Key {
                    depth: self.length() as u8,
                    fingerprint,
                    child: index,
                    chain,
                    data: secret.0.to_vec(),
                    hardened
                };
                Some(key.serialize(&self.chain.params))
            }
        }
    }

    pub fn serialized_extended_public_key(&self) -> Option<String> {
        //todo make sure this works with BLS keys
        if self.extended_public_key_data.len() < 36 {
            return None;
        }
        let fingerprint = self.extended_public_key_data.read_with::<u32>(&mut 0, byte::LE).unwrap();
        let chain = self.extended_public_key_data.read_with::<UInt256>(&mut 4, byte::LE).unwrap();
        let pub_key = self.extended_public_key_data.read_with::<ECPoint>(&mut 36, byte::LE).unwrap();
        let (child, is_hardened) = if self.is_empty() {
            (UInt256::MIN, false)
        } else {
            (self.indexes().last().unwrap().clone(), self.hardened_indexes().last().unwrap().clone())
        };
        // Some(bip32::Key::serialize(&self.chain.params))
        Some(StringKey::serialize(self.depth, fingerprint, is_hardened, child, chain, pub_key.as_bytes().to_vec(), &self.chain.params))
    }

    fn standalone_save_extended_public_key_to_keychain(&mut self) {
        if let (Some(ex_pk), Some(key)) = (&self.extended_public_key, self.standalone_extended_public_key_location_string()) {
            Keychain::set_data(key, self.extended_public_key_data(), false).expect("");
            let mut map = serde_json::Map::from_iter([
                (DERIVATION_PATH_STANDALONE_INFO_TERMINAL_HARDENED.to_owned(), json!(self.terminal_hardened())),
                (DERIVATION_PATH_STANDALONE_INFO_DEPTH.to_owned(), json!(self.depth)),
            ]);
            if let Some(&terminal_index) = self.indexes().last() {
                map.insert(DERIVATION_PATH_STANDALONE_INFO_TERMINAL_INDEX.to_owned(), json!(terminal_index.0.to_hex()));
            }
            if let Some(key) = self.standalone_info_dictionary_location_string() {
                Keychain::set_json(serde_json::Value::Object(map), key, false).expect("");
            }
            self.context().perform_block_and_wait(|context| {
                DerivationPathEntity::derivation_path_entity_matching_derivation_path(self, context).expect("");
            });
        }
    }

    pub fn wallet_based_extended_private_key_location_string(&mut self) -> String {
        if let Some(str) = &self.wallet_based_extended_private_key_location_string {
            str.clone()
        } else {
            let str = derivation::wallet_based_extended_private_key_location_string_for_unique_id(&self.wallet.unwrap().unique_id_string);
            self.wallet_based_extended_private_key_location_string = Some(str);
            str.clone()
        }
    }

    pub fn wallet_based_extended_public_key_location_string(&mut self) -> String {
        if let Some(str) = &self.wallet_based_extended_public_key_location_string {
            str.clone()
        } else {
            let str = derivation::wallet_based_extended_public_key_location_string_for_unique_id(&self.wallet.unwrap().unique_id_string);
            self.wallet_based_extended_public_key_location_string = Some(str);
            str.clone()
        }
    }
}

