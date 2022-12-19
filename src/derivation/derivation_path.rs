use std::collections::HashSet;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::derivation::derivation_path_feature_purpose::DerivationPathFeaturePurpose;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::uint256_index_path::{IIndexPath, IndexPath, UInt256IndexPath};
use crate::keychain::keychain::{Keychain, KeychainDictValueKind};
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::{IKey, Key};
use crate::keys::KeyType;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::wallet::Wallet;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::util;

pub const DERIVATION_PATH_EXTENDED_PUBLIC_KEY_WALLET_BASED_LOCATION: &str = "DP_EPK_WBL";
pub const DERIVATION_PATH_EXTENDED_PUBLIC_KEY_STANDALONE_BASED_LOCATION: &str = "DP_EPK_SBL";
pub const DERIVATION_PATH_EXTENDED_SECRET_KEY_WALLET_BASED_LOCATION: &str = "DP_ESK_WBL";
pub const DERIVATION_PATH_STANDALONE_INFO_DICTIONARY_LOCATION: &str = "DP_SIDL";
pub const DERIVATION_PATH_STANDALONE_INFO_TERMINAL_INDEX: &str = "DP_SI_T_INDEX";
pub const DERIVATION_PATH_STANDALONE_INFO_TERMINAL_HARDENED: &str = "DP_SI_T_HARDENED";
pub const DERIVATION_PATH_STANDALONE_INFO_DEPTH: &str = "DP_SI_DEPTH";

pub const BIP32_HARD: u32 = 0x80000000;
pub const BIP32_HARD_LE: u32 = 0x00000080;

pub enum Error {
    PublicKeyGenerationError(String),
    Default(&'static String),
    DefaultWithCode(&'static String, u32),
}

pub enum SequenceGapLimit {
    External,
    Internal,
    Initial
}

impl SequenceGapLimit {
    pub fn default(&self) -> u32 {
        match self {
            SequenceGapLimit::External => 10,
            SequenceGapLimit::Internal => 5,
            SequenceGapLimit::Initial => 100
        }
    }

    pub fn unused(&self) -> u32 {
        match self {
            SequenceGapLimit::External => 10,
            SequenceGapLimit::Internal => 5,
            SequenceGapLimit::Initial => 15
        }
    }

    pub fn dashpay(&self) -> u32 {
        match self {
            SequenceGapLimit::External => 6,
            SequenceGapLimit::Internal => 3,
            SequenceGapLimit::Initial => 10
        }
    }
}

pub enum DerivationPathKind {
    Default,
    SimpleIndexed,
    AuthenticationKeys,
    Funds,
    IncomingFunds,
    CreditFunding,
    MasternodeHoldings,
}

pub trait IDerivationPath {
    fn wallet(&self) -> Option<&Wallet>;
    fn signing_algorithm(&self) -> &KeyType;
    fn reference(&self) -> &DerivationPathReference;
    fn is_derivation_path_equal(&self, other: &dyn IDerivationPath) -> bool;
    fn has_extended_public_key(&self) -> bool;
    /// all previously generated addresses
    fn all_addresses(&self) -> HashSet<String>;
    /// all previously used addresses
    fn used_addresses(&self) -> HashSet<String>;
    fn contains_address(&self, address: Option<String>) -> bool;
    fn address_is_used(&self, address: Option<String>) -> bool;
    fn load_addresses(&mut self) {}
    fn reload_addresses(&mut self) {}

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String>;
    fn kind(&self) -> DerivationPathKind;
    fn balance(&self) -> u64;
    fn private_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey>;
    fn public_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey>;
    fn public_key_data_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<Vec<u8>>;
    // fn private_key_at_index_path<T>(&self, index_path: IndexPath<T>) -> Option<dyn IKey>;
    fn base_index_path<T>(&self) -> IndexPath<T>;
    fn index_path_for_known_address(&self, address: Option<String>) -> Option<IndexPath<u32>>;
    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey>;
    fn context(&self) -> &ManagedContext;

    fn register_transaction_address(&mut self, address: &String) -> bool;
    fn register_addresses_with_gap_limit(&mut self, gap_limit: u32) -> Result<Vec<String>, util::Error> {
        Err(util::Error::Default(&format!("Should be overriden")))
    }
}

#[derive(Clone, Copy, Debug)]
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
    extended_public_key: Option<dyn IKey>,

    pub standalone_extended_public_key_location_string: Option<String>,

    pub context: &'static ManagedContext,
    // @property (nonatomic, strong) NSManagedObjectContext *managedObjectContext;
    // @property (nonatomic, readonly) DSDerivationPathEntity *derivationPathEntity;

    /// private
    depth: u8,
    string_representation: Option<String>,
}

impl IIndexPath for DerivationPath {
    type Item = UInt256;

    fn new(indexes: Vec<Self::Item>) -> Self {
        Self { base: UInt256IndexPath { indexes }, ..Default::default() }
    }

    fn index_path_with_index(index: UInt256) -> Self {
        Self {
            base: UInt256IndexPath { indexes: vec![index] },
            ..Default::default()
        }
    }

    fn index_path_with_indexes(indexes: Vec<UInt256>) -> Self {
        Self { base: UInt256IndexPath { indexes }, ..Default::default() }
    }

    fn indexes(&self) -> &Vec<Self::Item> {
        &self.base.indexes
    }

    fn harden_all_items(&self) -> IndexPath<Self::Item> {
        // let indexes = self.inde
        NSUInteger indexes[[self length]];
        [self getIndexes:indexes];
        for (int i = 0; i < [self length]; i++) {
            indexes[i] |= BIP32_HARD;
        }
        return [NSIndexPath indexPathWithIndexes:indexes length:self.length];
    }

    fn soften_all_items(&self) -> IndexPath<Self::Item> {
        todo!()
    }
}


impl IDerivationPath for DerivationPath {
    fn signing_algorithm(&self) -> &KeyType {
        &self.signing_algorithm
    }

    fn reference(&self) -> &DerivationPathReference {
        &self.reference
    }

    fn is_derivation_path_equal(&self, other: &dyn IDerivationPath) -> bool {
        self == other
    }

    fn has_extended_public_key(&self) -> bool {
        if self.extended_public_key.is_some() {
            return true;
        }
        return if self.wallet.is_some() && (self.length() > 0 || self.reference == DerivationPathReference::Root) {
            Keychain::has_data(self.wallet_based_extended_public_key_location_string.unwrap()).unwrap_or(false)
        } else {
            Keychain::has_data(self.wallet_based_extended_public_key_location_string.unwrap()).unwrap_or(false)
        }
    }

    fn all_addresses(&self) -> HashSet<String> {
        todo!()
    }

    fn used_addresses(&self) -> HashSet<String> {
        todo!()
    }

    /// true if the address is controlled by the wallet
    fn contains_address(&self, address: Option<String>) -> bool {
        address.is_some() && self.all_addresses.contains(&address.unwrap())
    }

    // true if the address was previously used as an input or output in any wallet transaction
    fn address_is_used(&self, address: Option<String>) -> bool {
        address.is_some() && self.used_addresses().contains(&address.unwrap())
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        if let Some(&id) = &self.standalone_extended_public_key_unique_id {
            Some(id)
        } else if self.extended_public_key.is_none() && self.wallet.is_none() {
            assert!(false, "we really should have a wallet");
            None
        } else {
            let id = Some(self.create_identifier_for_derivation_path());
            self.standalone_extended_public_key_unique_id = id;
            id.clone()
        }
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::Default
    }

    fn balance(&self) -> u64 {
        self.balance
    }

    fn private_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        todo!()
    }

    fn public_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        self.signing_algorithm.public_key_from_extended_public_key_data(&self.extended_public_key_data, index_path)
    }

    fn base_index_path<T>(&self) -> IndexPath<T> {
        let mut indexes = Vec::<T>::with_capacity(self.length());
        (0..self.length()).for_each(|position| {
            if self.is_hardened_at_position(position) {
                //indexes[position] = [self indexAtPosition:position].u64[0] | BIP32_HARD;
                indexes.insert(position, self.index_at_position(position) | BIP32_HARD)
            } else {
                indexes.insert(position, self.index_at_position(position))
            }
        });
        IndexPath::index_path_with_indexes(indexes)
    }

    fn index_path_for_known_address(&self, address: Option<String>) -> Option<IndexPath<u32>> {
        todo!()
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.generate_extended_public_key_from_seed_and_store_private_key(seed, wallet_unique_id, false)
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

    fn public_key_data_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<Vec<u8>> {
        self.signing_algorithm().public_key_from_extended_public_key_data(&self.extended_public_key_data, index_path)
    }

    fn context(&self) -> &ManagedContext {
        self.context
    }

    fn private_keys_at_index_paths<T>(&self, index_paths: Vec<IndexPath<T>>, seed: Option<Vec<u8>>) -> Vec<&dyn IKey> {
        if seed.is_none() || index_paths
    }

    - (NSArray *)privateKeysAtIndexPaths:(NSArray *)indexPaths fromSeed:(NSData *)seed {
    if (!seed || !indexPaths) return nil;
    if (indexPaths.count == 0) return @[];
    NSMutableArray *privateKeys = [NSMutableArray arrayWithCapacity:indexPaths.count];
    DSKey *topKey = [DSKey keyWithSeedData:seed forKeyType:self.signingAlgorithm];
    DSKey *derivationPathExtendedKey = [topKey privateDeriveTo256BitDerivationPath:self];

    #if DEBUG
    if (_extendedPublicKey) {
    NSData *publicKey = _extendedPublicKey.extendedPublicKeyData;
    NSAssert([publicKey isEqualToData:derivationPathExtendedKey.extendedPublicKeyData], @"The derivation doesn't match the public key");
    }
    #endif

    for (NSIndexPath *indexPath in indexPaths) {
    DSKey *privateKey = [derivationPathExtendedKey privateDeriveToPath:indexPath];
    [privateKeys addObject:privateKey];
    }

    return privateKeys;
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        // todo: avoid clone & optioning address
        if self.contains_address(Some(address.clone())) {
            if !self.used_addresses.contains(address) {
                self.used_addresses.push(address.clone());
            }
            true
        }
        false
    }

}

impl DerivationPath {

    pub fn serialized_private_keys_at_index_paths<T>(&self, index_paths: Vec<IndexPath<T>>, seed: Option<Vec<u8>>) -> Option<Vec<String>> {
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
        let derivation_path_extended_key_opt = top_key_opt.unwrap().private_derive_to256bit_derivation_path(self);
        if derivation_path_extended_key_opt.is_none() {
            return Some(vec![]);
        }
        let derivation_path_extended_key = derivation_path_extended_key_opt.unwrap();
        index_paths.iter().filter_map(|index_path| {
            if let Some(privateKey) = derivation_path_extended_key.private_derive_to_path(index_path) {
                privateKey.serialized_private_key_for_chain(self.chain)
            } else {
                assert!(false, "The serialized private key should exist");
                None
            }
        }).collect()
    }


    pub fn standalone_extended_public_key_location_string_for_unique_id(unique_id: &String) -> String {
        format!("{}_{}", DERIVATION_PATH_EXTENDED_PUBLIC_KEY_STANDALONE_BASED_LOCATION, unique_id)
    }

    pub fn standalone_info_dictionary_location_string_for_unique_id(unique_id: String) -> String {
        format!("{}_{}", DERIVATION_PATH_STANDALONE_INFO_DICTIONARY_LOCATION, unique_id)
    }

    pub fn wallet_based_extended_public_key_location_string_for_unique_id(unique_id: String) -> String {
        format!("{}_{}", DERIVATION_PATH_EXTENDED_PUBLIC_KEY_WALLET_BASED_LOCATION, unique_id)
    }

    pub fn create_identifier_for_derivation_path(&self) -> String {
        //return [NSData dataWithUInt256:[[self extendedPublicKeyData] SHA256]].shortHexString;
        todo!()
    }

    pub fn standalone_extended_public_key_location_string(&self) -> Option<String> {
        if let Some(&unique_id) = &self.standalone_extended_public_key_unique_id {
            Some(Self::standalone_extended_public_key_location_string_for_unique_id(unique_id))
        } else {
            None
        }
    }

    pub fn standalone_info_dictionary_location_string(&self) -> Option<String> {
        if let Some(&unique_id) = &self.standalone_extended_public_key_unique_id {
            Some(Self::standalone_info_dictionary_location_string_for_unique_id(unique_id))
        } else {
            None
        }
    }

    pub fn init_with_extended_public_key_identifier(extended_public_key_identifier: String, chain: &Chain) -> Option<Self> {
        let key = Self::standalone_info_dictionary_location_string_for_unique_id(extended_public_key_identifier);
        if let Some(info_dictionary) = Keychain::get_dict::<String, KeychainDictValueKind>(key, vec!["String".to_string(), "Number".to_string()]) {
            let terminal_index =
                if let &KeychainDictValueKind::Uint256(terminal_index) = info_dictionary.get(DERIVATION_PATH_STANDALONE_INFO_TERMINAL_INDEX) {
                    Some(terminal_index)
                } else {
                    None
                };

            let terminal_hardened = if let &KeychainDictValueKind::Bool(terminal_hardened) = info_dictionary.get(DERIVATION_PATH_STANDALONE_INFO_TERMINAL_HARDENED) {
                Some(terminal_hardened)
            } else {
                None
            };
            if terminal_index.is_none() || terminal_hardened.is_none() {
                return None;
            }
            // TODO: length here is zero! so is not based on indexes length?
            let mut s = Self {
                base: UInt256IndexPath { indexes: vec![terminal_index.unwrap()] },
                hardened_indexes: vec![terminal_hardened.unwrap()],
                r#type: DerivationPathType::ViewOnlyFunds,
                signing_algorithm: KeyType::ECDSA,
                reference: DerivationPathReference::Unknown,
                chain,

                account: None,
                wallet: None,
                extended_public_key_data: vec![],
                standalone_extended_public_key_unique_id: None,
                wallet_based_extended_public_key_location_string: None,
                wallet_based_extended_private_key_location_string: None,
                balance: 0,
                purpose: 0,
                sync_block_height: 0,
                derivation_path_is_known: false,
                addresses_loaded: false,
                all_addresses: vec![],
                extended_public_key: None,
                standalone_extended_public_key_location_string: None,
                depth: 0,
                string_representation: None
            };
            if let Some(data) = Keychain::get_data(Self::standalone_extended_public_key_location_string_for_unique_id(&extended_public_key_identifier)) {
                // TODO: impl DSKey wrapper
                //s.extended_public_key = Some([DSKey keyWithExtendedPublicKeyData:data forKeyType:DSKeyType_ECDSA]);

                if let &KeychainDictValueKind::Byte(depth) = info_dictionary.get(DERIVATION_PATH_STANDALONE_INFO_DEPTH) {
                    s.depth = depth
                } else {
                    return None;
                };
                s.load_addresses();
                return Some(s);
            } else {
                return None;
            }

        } else {
            return None;
        }
    }

    pub fn derivation_path_with_indexes(indexes: Vec<UInt256>, hardened: Vec<bool>, r#type: DerivationPathType, signing_algorithm: KeyType, reference: DerivationPathReference, chain: &Chain) -> Self {
        return [[self alloc] initWithIndexes:indexes hardened:hardenedIndexes length:length type:type signingAlgorithm:signingAlgorithm reference:reference onChain:chain];
    }

    pub fn master_blockchain_identity_contacts_derivation_path_for_account_number(account_number: u32, chain: &Chain) -> Self {
        let coin_type = if chain.is_mainnet() { 5 } else { 1 };
        let indexes = vec![
            UInt256::from_u32(DerivationPathFeaturePurpose::DEFAULT.into()).unwrap(),
            UInt256::from_u32(coin_type).unwrap(),
            UInt256::from_u32(DerivationPathFeaturePurpose::DASHPAY.into()).unwrap(),
            UInt256::from_u32(account_number).unwrap(),
        ];
        // TODO: full uint256 derivation
        let hardened = vec![true, true, true, true];
        let r#type = DerivationPathType::PartialPath;
        let signing_algorithm = KeyType::ECDSA;
        let reference = DerivationPathReference::ContactBasedFundsRoot;
        Self::derivation_path_with_indexes(indexes, hardened, r#type, signing_algorithm, reference, chain)
    }

    /// this returns the derivation path's visual representation (e.g. m/44'/5'/0')
    pub fn string_representation(&self) -> &str {
        if let Some(rep) = &self.string_representation {
            return rep.as_str()
        }
        let mut mutable_string = "m";
        if self.length() > 0 {
            self.base.indexes.iter().for_each(|index| {
                mutable_string += "";
            });
            for (NSInteger i = 0; i < self.length; i++) {
                [mutable_string
                appendString:[DSDerivationPath stringRepresentationOfIndex:[self indexAtPosition:i] hardened:[self isHardenedAtPosition:i] inContext:self.managedObjectContext]];
            }
        } else if ([self.depth integerValue]) {
            for (NSInteger i = 0; i < [self.depth integerValue] - 1; i++) {
                [mutableString appendFormat:@"/?'"];
            }
            UInt256 terminalIndex = [self terminalIndex];
            BOOL terminalHardened = [self terminalHardened];
            [mutableString appendString:[DSDerivationPath stringRepresentationOfIndex:terminalIndex hardened:terminalHardened inContext:self.managedObjectContext]];
        } else {
            if ([self isKindOfClass:[DSIncomingFundsDerivationPath class]]) {
                mutableString = [NSMutableString stringWithFormat:@"inc"];
                DSIncomingFundsDerivationPath *incomingFundsDerivationPath = (DSIncomingFundsDerivationPath *)self;
                [self.managedObjectContext performBlockAndWait:^{
                    DSDashpayUserEntity *sourceDashpayUserEntity = [DSDashpayUserEntity anyObjectInContext:self.managedObjectContext matching:@"associatedBlockchainIdentity.uniqueID == %@", uint256_data(incomingFundsDerivationPath.contactSourceBlockchainIdentityUniqueId)];
                    if (sourceDashpayUserEntity) {
                        DSBlockchainIdentityUsernameEntity *usernameEntity = [sourceDashpayUserEntity.associatedBlockchainIdentity.usernames anyObject];
                        [mutableString appendFormat:@"/%@", usernameEntity.stringValue];
                    } else {
                        [mutableString appendFormat:@"/0x%@", uint256_hex(incomingFundsDerivationPath.contactSourceBlockchainIdentityUniqueId)];
                    }
                }];
                DSBlockchainIdentity *blockchainIdentity = [self.wallet blockchainIdentityForUniqueId:incomingFundsDerivationPath.contactDestinationBlockchainIdentityUniqueId];
                [mutableString appendFormat:@"/%@", blockchainIdentity.currentDashpayUsername];
            }
        }
        _stringRepresentation = [mutable_string copy];
        return _stringRepresentation;

    }

    // gets an address at an index path
    pub fn address_at_index_path(&self, index_path: &dyn IIndexPath) -> Option<String> {
        todo!();
        // let pub_key = self.public_key_data_at_index_path(index_path);
        // return [DSKey addressWithPublicKeyData:pubKey forChain:self.chain];
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

    pub fn wallet_based_extended_public_key_location_string_for_wallet_unique_id(&self, unique_id: String) -> String {
        format!("{}{}{}",
                Self::wallet_based_extended_public_key_location_string_for_unique_id(unique_id),
                if self.signing_algorithm == KeyType::ECDSA { "" } else { "_BLS_" },
                self.base.indexes.into_iter()
                    .map(|index|
                        format!("_{}", if self.is_hardened_at_position(index) { self.index_at_position(index).u64[0] | BIP32_HARD } else { self.index_at_position(index).u64[0] }))
                    .join(".")
        )
    }



    /// Key Generation

    pub fn generate_extended_public_key_from_seed_and_store_private_key(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>, store_private_key: bool) -> Option<&dyn IKey> {
        if seed.is_empty() || (self.is_empty() && self.reference != DerivationPathReference::Root) {
            return None;
        }
        if let Some(seed_key) = self.signing_algorithm().key_with_seed_data(seed) {
            self.extended_public_key = seed_key.private_derive_to256bit_derivation_path(self);
            assert!(self.extended_public_key.is_some(), "extendedPublicKey should be set");
            if let Some(extended_public_key) = &self.extended_public_key {
                if let Some(unique_id) = wallet_unique_id {
                    Keychain::set_data(
                        self.wallet_based_extended_public_key_location_string_for_wallet_unique_id(unique_id),
                        Some(extended_public_key.extended_public_key_data().clone()),
                        false)
                        .expect("Can't store extended_public_key_data in keychain");
                    if store_private_key {
                        Keychain::set_data(
                            self.wallet_based_extended_private_key_location_string_for_wallet_unique_id(unique_id),
                            Some(extended_public_key.extended_private_key_data().clone()),
                            true)
                            .expect("Can't store extended_public_key_data in keychain");
                    }
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


}

