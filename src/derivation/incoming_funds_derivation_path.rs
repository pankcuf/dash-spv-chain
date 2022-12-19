use std::collections::HashSet;
use std::usize;
use crate::chain::chain::Chain;
use crate::chain::extension::identities::Identities;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::UInt256;
use crate::derivation::derivation_path::{DerivationPath, DerivationPathKind, Error, IDerivationPath, SequenceGapLimit};
use crate::derivation::derivation_path_feature_purpose::DerivationPathFeaturePurpose;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::uint256_index_path::{IIndexPath, IndexPath};
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::platform::identity::identity::Identity;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::storage::models::tx::transaction_output::TransactionOutputEntity;
use crate::util::crypto::{address_with_public_key_data, is_valid_dash_address_on_chain};


#[derive(Clone, Copy, Debug)]
pub struct IncomingFundsDerivationPath {
    pub base: DerivationPath,
    pub contact_source_blockchain_identity_unique_id: UInt256,
    pub contact_destination_blockchain_identity_unique_id: UInt256,
    pub contact_source_blockchain_identity: Identity,
    pub contact_destination_blockchain_identity: Identity,
    pub source_is_local: bool,
    pub destination_is_local: bool,

    external_derivation_path: bool,
    external_addresses: Vec<String>,
    // @property (atomic, strong) NSMutableArray *externalAddresses;

}

impl IncomingFundsDerivationPath {
    pub(crate) fn contact_based_derivation_path_with_destination_identity_unique_id(
        destination_identity_unique_id: UInt256,
        source_identity_unique_id: UInt256,
        account_number: u32,
        chain: &Chain) -> Self {
        assert_ne!(source_identity_unique_id, destination_identity_unique_id, "source and destination must be different");
        //todo full uint256 derivation
        Self {
            base: DerivationPath::derivation_path_with_indexes(
                vec![
                    UInt256::from_u64(DerivationPathFeaturePurpose::DEFAULT.into()).unwrap(),
                    UInt256::from_u64(if chain.is_mainnet() { 5 } else { 1 }).unwrap(),
                    UInt256::from_u64(DerivationPathFeaturePurpose::DASHPAY.into()).unwrap(),
                    UInt256::from_u64(account_number).unwrap(),
                    source_identity_unique_id,
                    destination_identity_unique_id,
                ],
                vec![true, true, true, true, false, false],
                DerivationPathType::ClearFunds,
                KeyType::ECDSA,
                DerivationPathReference::ContactBasedFunds,
                chain),
            contact_source_blockchain_identity_unique_id: source_identity_unique_id,
            contact_destination_blockchain_identity_unique_id: destination_identity_unique_id,
            ..Default::default()
        }
    }

    pub(crate) fn external_derivation_path_with_extended_public_key_unique_id(public_key_identifier: &String, destination_identity_unique_id: UInt256, source_identity_unique_id: UInt256, chain: &Chain) -> Self {
        // we are going to assume this is only ecdsa for now
        Self {
            base: DerivationPath::derivation_path_with_indexes(
                vec![],
                vec![],
                DerivationPathType::ViewOnlyFunds,
                KeyType::ECDSA,
                DerivationPathReference::ContactBasedFundsExternal,
                chain),
            contact_source_blockchain_identity_unique_id: source_identity_unique_id,
            contact_destination_blockchain_identity_unique_id: destination_identity_unique_id,
            external_derivation_path: true,
            ..Default::default()
        }
    }

    pub fn load_addresses_in_context(&mut self, context: &ManagedContext) {
        if !self.base.addresses_loaded {
            match DerivationPathEntity::derivation_path_entity_matching_derivation_path(self, context) {
                Ok(derivation_path_entity) => {
                    self.base.sync_block_height = derivation_path_entity.sync_block_height as u32;
                    match derivation_path_entity.get_addresses(context) {
                        Ok(addresses) => {
                            for e in addresses {
                                let mut a = self.external_addresses.clone();
                                while e.index as usize >= a.len() {
                                    a.push(None);
                                }
                                if !is_valid_dash_address_on_chain(&e.address, self.base.account.unwrap().wallet.unwrap().chain) {
                                    continue;
                                }
                                a[e.index] = Some(e.address);
                                self.base.all_addresses.push(e.address.clone());
                               if e.count_used_in_inputs(context).unwrap_or(0) > 0 || e.count_used_in_outputs(context).unwrap_or(0) > 0 {
                                   self.base.used_addresses.push(e.address.clone());
                               }

                                if let Ok(count @ 1..usize::MAX) = e.count_used_in_inputs(context) {}
                            }
                            self.base.addresses_loaded = true;
                            let _ = self.register_addresses_with_gap_limit(SequenceGapLimit::Intial.dashpay(), context);
                        },
                        Err(err) => println!("Error retrieving addresses for derivation path entity {:?}", self)
                    }
                },
                Err(err) => println!("Error retrieving derivation path entity for {:?}", self)
            }
        }
    }


    // Wallets are composed of chains of addresses. Each chain is traversed until a gap of a certain number of addresses is
    // found that haven't been used in any transactions. This method returns an array of <gapLimit> unused addresses
    // following the last used address in the chain. The internal chain is used for change addresses and the external chain
    // for receive addresses.
    pub fn register_addresses_with_gap_limit(&mut self, gap_limit: u32, context: &ManagedContext) -> Result<Vec<String>, Error> {
        assert!(self.base.account.is_some(), "Account must be set");
        if !self.base.account.unwrap().wallet.unwrap().is_transient {
            if !self.base.addresses_loaded {
                //sleep(1); //quite hacky, we need to fix this
                // todo: impl
                return self.register_addresses_with_gap_limit(gap_limit, context);
            }
            assert!(self.base.addresses_loaded, "addresses must be loaded before calling this function");
        }
        let mut array = self.external_addresses.clone();
        let mut i = a.len();

        // keep only the trailing contiguous block of addresses with no transactions
        while i > 0 && !self.base.used_addresses.contains(&a.get(i - 1).unwrap()) {
            i -= 1;
        }
        if i > 0 {
            array.drain(0..i);
        }
        if array.len() >= gap_limit as usize {
            return Ok(array.drain(0..gap_limit).collect());
        }

        if gap_limit > 1 {
            // get receiveAddress and changeAddress first to avoid blocking
            let _ = self.receive_address_in_context(context);
        }

        /// It seems weird to repeat this, but it's correct because of the original call receive address and change address
        array = self.external_addresses.clone();
        i = array.len();

        let mut n = i as u32;

        // keep only the trailing contiguous block of addresses with no transactions
        while i > 0 && !self.used_addresses().contains(array.get(i - 1).unwrap()) {
            i -= 1;
        }
        if i > 0 {
            array.drain(0..i);
        }
        if array.len() >= gap_limit as usize {
            return Ok(array.drain(0..gap_limit).collect());
        }
        let mut upper_limit = gap_limit;
        while array.len() < upper_limit as usize {
            // generate new addresses up to gapLimit
            if let Some(pub_key_data) = self.public_key_data_at_index(n) {
                let pub_key = KeyType::ECDSA.key_with_public_key_data(&pub_key_data);
                if let Some(address) = address_with_public_key_data(&pub_key_data, self.base.chain) {
                    let mut is_used = false;
                    if !self.base.account.unwrap().wallet.unwrap().is_transient {
                        // store new address in core data
                        match DerivationPathEntity::derivation_path_entity_matching_derivation_path(self, context) {
                            Ok(derivation_path_entity) => {
                                match AddressEntity::create_with(derivation_path_entity.id, address.as_str(), n as i32, false, false, context) {
                                    Ok(created) => {
                                        // todo: address: string vs bytes
                                        match TransactionOutputEntity::get_by_address(&address.as_bytes().to_vec(), context) {
                                            Ok(outputs) => {
                                                // [e addUsedInOutputs:[NSSet setWithArray:outputs]];
                                                if !outputs.is_empty() {
                                                    is_used = true;
                                                }
                                            },
                                            Err(err) => Err(Error::Default(&format!("Can't retrieve transaction output entities for {:?}", &address)))
                                        }
                                    },
                                    Err(err) => Err(Error::Default(&format!("Can't create address entity for {:?}", derivation_path_entity)))
                                }
                            },
                            Err(err) => Err(Error::Default(&format!("Can't retrieve derivation path entity for {:?}", self)))
                        }
                    }
                    if is_used {
                        self.base.used_addresses.push(address);
                        upper_limit += 1;
                    }
                    self.base.all_addresses.push(address.clone());
                    self.external_addresses.push(address.clone());
                    array.push(address.clone());
                    n += 1;
                }
            } else {
                println!("error generating keys");
                return Err(Error::DefaultWithCode(&format!("Error generating public keys"), 500));
            }
        }
        Ok(array)
    }

    /// gets an address at an index path
    pub fn address_at_index(&self, index: u32) -> Option<String> {
        let pub_key = self.base.public_key_data_at_index(index);
        address_with_public_key_data(pub_key, self.base.chain)
        // NSData *pubKey = [self publicKeyDataAtIndex:index];
        // return [[DSECDSAKey keyWithPublicKeyData:pubKey] addressForChain:self.chain];
    }

    /// returns the first unused external address
    pub fn receive_address(&mut self) -> Option<String> {
        self.receive_address_in_context(self.base.context)
    }

    pub fn receive_address_in_context(&mut self, context: &ManagedContext) -> Option<String> {
        self.receive_address_at_offset_in_context(0, context)
    }

    pub fn receive_address_at_offset(&mut self, offset: u32) -> Option<String> {
        self.receive_address_at_offset_in_context(offset, self.base.context)
    }

    pub fn receive_address_at_offset_in_context(&mut self, offset: u32, context: &ManagedContext) -> Option<String> {
        // TODO: limit to 10,000 total addresses and utxos for practical usability with bloom filters
        if let Ok(addresses) = self.register_addresses_with_gap_limit(offset + 1, context) {
            if let Some(addr) = addresses.last() {
                return Some(addr.clone());
            }
        }
        if let Some(addr) = self.all_receive_addresses().last() {
            return addr.clone();
        }
        None
    }

    /// all previously generated external addresses
    pub fn all_receive_addresses(&self) -> Vec<Option<String>> {
        self.external_addresses.clone()
    }

    pub fn used_receive_addresses(&self) -> Vec<Option<String>> {
        HashSet::from(self.all_receive_addresses()).intersection(HashSet::from(self.base.used_addresses)).collect()
    }


    pub fn public_key_data_at_index(&self, index: u32) -> Option<Vec<u8>> {
        self.public_key_data_at_index_path(&IndexPath::index_path_with_indexes(vec![index]))
    }

    pub fn private_key_string_at_index(&self, index: u32, seed: Option<Vec<u8>>) -> Option<&String> {
        self.serialized_private_keys(vec![index], seed).and_then(|keys| keys.last())
    }

    pub fn private_keys(&self, indexes: Vec<u32>, seed: Option<Vec<u8>>) -> Vec<&dyn IKey> {
        self.base.private_keys_at_index_paths(indexes.iter().map(|&index| IndexPath::index_path_with_indexes(vec![index])).collect(), seed)
    }

    pub fn serialized_private_keys(&self, indexes: Vec<u32>, seed: Option<Vec<u8>>) -> Option<Vec<String>> {
        self.base.serialized_private_keys_at_index_paths(indexes.iter().map(|&index| IndexPath::index_path_with_indexes(vec![index])).collect(), seed)
    }

    pub fn index_path_for_known_address(&self, address: Option<String>) -> Option<IndexPath<u32>> {
        if let Some(pos) = self.all_receive_addresses().iter().position(|x| x == address) {
            Some(IndexPath::index_path_with_indexes(vec![pos as u32]))
        } else {
            None
        }
    }

    pub fn contact_source_blockchain_identity(&self) -> Option<&Identity> {
        if let Some((identity, wallet)) = self.base.chain.blockchain_identity_for_unique_id_in_wallet_including_foreign_identites(self.contact_source_blockchain_identity_unique_id, true) {
            Some(identity)
        } else {
            None
        }
    }

    pub fn contact_destination_blockchain_identity(&self) -> Option<&Identity> {
        if let Some((identity, wallet)) = self.base.chain.blockchain_identity_for_unique_id_in_wallet_including_foreign_identites(self.contact_destination_blockchain_identity_unique_id, true) {
            Some(identity)
        } else {
            None
        }
    }

}

impl IDerivationPath for IncomingFundsDerivationPath {
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
        todo!()
    }

    fn address_is_used(&self, address: Option<String>) -> bool {
        todo!()
    }

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.base.standalone_extended_public_key_unique_id()
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::IncomingFunds
    }

    fn balance(&self) -> u64 {
        todo!()
    }

    fn private_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        todo!()
    }

    fn public_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        self.base.public_key_at_index_path(index_path)
    }

    fn public_key_data_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<Vec<u8>> {
        self.base.public_key_data_at_index_path(index_path)
    }

    fn base_index_path<T>(&self) -> IndexPath<T> {
        todo!()
    }

    fn index_path_for_known_address(&self, address: Option<String>) -> Option<IndexPath<u32>> {
        todo!()
    }

    fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        todo!()
    }

    fn context(&self) -> &ManagedContext {
        self.base.context()
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        // todo: avoid clone & optioning address
        if self.contains_address(Some(address.clone())) {
            if !self.used_addresses.contains(address) {
                self.used_addresses.push(address.clone());
                let _ = self.register_addresses_with_gap_limit(SequenceGapLimit::External.default(), self.context());
            }
            true
        }
        false
    }
}
