use std::collections::{HashMap, HashSet};
use crate::crypto::{UInt160, UInt256};
use crate::chain::chain::Chain;
use crate::derivation::derivation_path::{DerivationPath, DerivationPathKind, IDerivationPath};
use crate::derivation::simple_indexed_derivation_path::{ISimpleIndexedDerivationPath, SimpleIndexedDerivationPath};
use crate::derivation::uint256_index_path::{IIndexPath, IndexPath};
use crate::keychain::keychain::{Keychain, KeychainError};
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::chain::wallet::wallet::Wallet;
use crate::derivation::derivation_path_feature_purpose::DerivationPathFeaturePurpose;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;

pub struct AuthenticationKeysDerivationPath {
    pub base: SimpleIndexedDerivationPath,
    pub has_extended_private_key: bool,
    pub uses_hardened_keys: bool,

    should_store_extended_private_key: bool,
    addresses_by_identity: HashMap<u32, Vec<String>>,
}

impl IDerivationPath for AuthenticationKeysDerivationPath {
    fn signing_algorithm(&self) -> &KeyType {
        self.base.signing_algorithm()
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
        DerivationPathKind::AuthenticationKeys
    }

    fn balance(&self) -> u64 {
        self.base.balance()
    }

    fn private_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        todo!()
    }

    fn public_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        todo!()
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
}

impl ISimpleIndexedDerivationPath for AuthenticationKeysDerivationPath {
    fn addresses_to_index(&self, index: u32) -> HashSet<String> {
        self.base.addresses_to_index(index)
    }

    fn addresses_to_index_using_cache(&self, index: u32, use_cache: bool, add_to_cache: bool) -> HashSet<String> {
        self.base.addresses_to_index_using_cache(index, use_cache, add_to_cache)
    }

    fn address_at_index(&self, index: u32) -> Option<String> {
        self.base.address_at_index(index)
    }

    fn address_is_used_at_index(&self, index: u32) -> bool {
        self.base.address_is_used_at_index(index)
    }

    fn index_path_of_known_address(&self, address: String) -> Option<dyn IIndexPath> {
        self.base.index_path_of_known_address(address)
    }

    fn index_of_known_address(&self, address: Option<String>) -> Option<u32> {
        self.base.index_of_known_address(address)
    }

    fn public_key_data_at_index(&self, index: u32) -> Option<Vec<u8>> {
        self.base.public_key_data_at_index(index)
    }
}

impl AuthenticationKeysDerivationPath {

    pub fn provider_voting_keys_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        todo!()
        //return [[DSDerivationPathFactory sharedInstance] providerVotingKeysDerivationPathForWallet:wallet];
    }

    pub fn provider_owner_keys_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        todo!()
    }

    pub fn provider_operator_keys_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        todo!()
    }

    pub fn blockchain_identities_bls_keys_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        todo!()
    }

    pub fn blockchain_identities_ecdsa_keys_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        todo!()
    }

    pub fn first_unused_public_key(&self) -> Vec<u8> {
        todo!()
    }

    pub fn first_unused_private_key_from_seed(&self, seed: Vec<u8>) -> DSKey {
        todo!()
    }

    pub fn private_key_for_address(&self, address: String, seed: Vec<u8>) -> DSKey {
        todo!()
    }

    pub fn private_key_for_hash160(&self, hash160: UInt160, seed: Vec<u8>) -> DSKey {
        todo!()
    }

    pub fn public_key_data_for_hash160(&self, hash: UInt160) -> Vec<u8> {
        todo!()
    }

    fn extended_private_key_data(&self) -> Option<Vec<u8>> {
        Keychain::get_data(self.wallet_based_extended_private_key_location_string()).ok()
}

    pub fn private_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        self.extended_private_key_data()
            .and_then(|data| self.signing_algorithm().private_key_from_extended_private_key_data(&data, index_path)
                .and_then(|key| key.private_derive_to_path(index_path)))
    }

    pub fn private_key_at_index_path_from_seed(&self, index_path: &IndexPath<u32>, seed: Option<&Vec<u8>>) -> Option<dyn IKey> {
        //if (!seed || !indexPath) return nil;
        if self.length() == 0 {
            // there needs to be at least 1 length
            return None;
        }
        if let Some(seed) = seed {
            if let Some(top_key) = self.signing_algorithm().key_with_seed_data(seed) {
                if let Some(derivationPathExtendedKey) = top_key.private_derive_to256bit_derivation_path(self) {
                    return derivationPathExtendedKey.private_derive_to_path(index_path)
                } else {
                    assert!(false, "Derivation Path should exist")
                }
            } else {
                assert!(false, "Top key should exist")
            }
        } else {
            assert!(false, "Seed should exist")
        }
        None
    }

    fn keys_derivation_path_for_chain(
        indexes: Vec<UInt256>,
        hardened: Vec<bool>,
        r#type: DerivationPathType,
        signing_algorithm: KeyType,
        reference: DerivationPathReference,
        should_store_extended_private_key: bool,
        uses_hardened_keys: bool,
        chain: &Chain) -> Self {
        Self {
            base: SimpleIndexedDerivationPath {
                base: DerivationPath::derivation_path_with_indexes(
                    indexes,
                    hardened,
                    r#type,
                    signing_algorithm,
                    reference,
                    chain
                )
            },
            should_store_extended_private_key,
            uses_hardened_keys,
            ..Default::default()
        }
    }

    fn provider_keys_derivation_path_for_chain(
        reference: DerivationPathReference,
        signing_algorithm: KeyType,
        last_index: u32,
        chain: &Chain) -> Self {
        Self::keys_derivation_path_for_chain(
            vec![
                UInt256::from_u32(DerivationPathFeaturePurpose::DEFAULT.into()),
                UInt256::from_u32(chain.params.chain_type.coin_type()),
                UInt256::from_u32(3),
                UInt256::from_u32(last_index)
            ],
            vec![true, true, true, true],
            DerivationPathType::SingleUserAuthentication,
            signing_algorithm,
            reference,
            false,
            false,
            chain,
        )
    }

    fn blockchain_identity_keys_derivation_path_for_chain(signing_algorithm: KeyType, last_index: u32, chain: &Chain) -> Self {
        Self::keys_derivation_path_for_chain(
            vec![
                UInt256::from_u32(DerivationPathFeaturePurpose::DEFAULT.into()),
                UInt256::from_u32(chain.params.chain_type.coin_type()),
                UInt256::from_u32(DerivationPathFeaturePurpose::IDENTITIES.into()),
                UInt256::from_u32(DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_AUTHENTICATION.into()),
                UInt256::from_u32(last_index)
            ],
            vec![true, true, true, true, true],
            DerivationPathType::MultipleUserAuthentication,
            signing_algorithm,
            DerivationPathReference::BlockchainIdentities,
            true,
            true,
            chain,
        )
    }

    pub fn provider_voting_keys_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::provider_keys_derivation_path_for_chain(DerivationPathReference::ProviderVotingKeys, KeyType::ECDSA, 1, chain)
    }

    pub fn provider_owner_keys_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::provider_keys_derivation_path_for_chain(DerivationPathReference::ProviderOwnerKeys, KeyType::ECDSA, 2, chain)
    }

    pub fn provider_operator_keys_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::provider_keys_derivation_path_for_chain(DerivationPathReference::ProviderOperatorKeys, KeyType::BLS, 3, chain)
    }

    pub fn identity_ecdsa_keys_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::blockchain_identity_keys_derivation_path_for_chain(KeyType::ECDSA, 0, chain)
    }

    pub fn identity_bls_keys_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::blockchain_identity_keys_derivation_path_for_chain(KeyType::BLS, 1, chain)
    }

    pub fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.base.base.generate_extended_public_key_from_seed_and_store_private_key(seed, wallet_unique_id, self.should_store_extended_private_key)
    }

}
