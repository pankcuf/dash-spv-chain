use std::collections::HashSet;
use crate::chain::chain::Chain;
use crate::derivation::derivation_path::{DerivationPathKind, IDerivationPath};
use crate::derivation::simple_indexed_derivation_path::{ISimpleIndexedDerivationPath, SimpleIndexedDerivationPath};
use crate::derivation::uint256_index_path::IIndexPath;
use crate::chain::wallet::wallet::Wallet;
use crate::keys::key::IKey;

pub struct MasternodeHoldingsDerivationPath {
    pub base: SimpleIndexedDerivationPath,
}

impl IDerivationPath for MasternodeHoldingsDerivationPath {
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

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.base.standalone_extended_public_key_unique_id()
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::MasternodeHoldings
    }

    fn balance(&self) -> u64 {
        self.base.balance()
    }
}

impl ISimpleIndexedDerivationPath for MasternodeHoldingsDerivationPath {
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


impl MasternodeHoldingsDerivationPath {

    pub fn provider_funds_derivation_path_for_chain(chain: &Chain) -> Self {
        todo!()
    }
    pub fn provider_funds_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        todo!()
    }

    pub fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.base.base.generate_extended_public_key_from_seed_and_store_private_key(seed, wallet_unique_id, false)
    }

}
