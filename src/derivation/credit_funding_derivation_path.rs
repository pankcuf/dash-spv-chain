use std::collections::HashSet;
use crate::crypto::{UInt160, UInt256};
use crate::chain::chain::Chain;
use crate::chain::wallet::wallet::Wallet;
use crate::derivation::derivation_path::{DerivationPath, IDerivationPath};
use crate::derivation::derivation_path_feature_purpose::DerivationPathFeaturePurpose;
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::simple_indexed_derivation_path::{ISimpleIndexedDerivationPath, SimpleIndexedDerivationPath};
use crate::derivation::index_path::{IIndexPath, IndexPath};
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::storage::manager::managed_context::ManagedContext;

#[derive(Debug, Default, PartialEq)]
pub struct CreditFundingDerivationPath {
    pub base: SimpleIndexedDerivationPath,
}

// impl IIndexPath for CreditFundingDerivationPath {
//     type Item = UInt256;
//
//     fn new(indexes: Vec<Self::Item>) -> Self {
//         Self::b
//     }
//
//     fn index_at_position(&self, position: usize) -> Self::Item {
//         self.base.base.index_at_position(position)
//     }
//
//     fn indexes(&self) -> &Vec<Self::Item> {
//         self.b
//     }
// }

impl IDerivationPath for CreditFundingDerivationPath {
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
        DerivationPathKind::CreditFunding
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
        self.base.base.generate_extended_public_key_from_seed_and_store_private_key(seed, wallet_unique_id, false)
    }

    fn register_transaction_address(&mut self, address: &String) -> bool {
        self.base.register_transaction_address(address)
    }
}

impl ISimpleIndexedDerivationPath for CreditFundingDerivationPath {

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
}

impl CreditFundingDerivationPath {
    fn identity_funding_derivation_path_for_chain(reference: DerivationPathReference, last_index: u32, chain: &Chain) -> Self {
        Self {
            base: SimpleIndexedDerivationPath {
                base: DerivationPath::derivation_path_with_indexes(
                    vec![
                        DerivationPathFeaturePurpose::Default.into_u256(),
                        UInt256::from(chain.r#type().coin_type()),
                        DerivationPathFeaturePurpose::Identities.into_u256(),
                        UInt256::from(last_index),
                    ],
                    vec![true, true, true, true],
                    DerivationPathType::CreditFunding,
                    KeyType::ECDSA,
                    reference,
                    chain
                ),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn identity_registration_funding_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::identity_funding_derivation_path_for_chain(
            DerivationPathReference::BlockchainIdentityCreditRegistrationFunding,
            DerivationPathFeaturePurpose::IdentitiesSubfeatureRegistration.into(),
            chain
        )
    }

    pub fn identity_topup_funding_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::identity_funding_derivation_path_for_chain(
            DerivationPathReference::BlockchainIdentityCreditTopupFunding,
            DerivationPathFeaturePurpose::IdentitiesSubfeatureTopup.into(),
            chain
        )
    }

    pub fn identity_invitation_funding_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::identity_funding_derivation_path_for_chain(
            DerivationPathReference::BlockchainIdentityCreditInvitationFunding,
            DerivationPathFeaturePurpose::IdentitiesSubfeatureInvitations.into(),
            chain
        )
    }

    pub fn identity_registration_funding_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        let mut path = Self::identity_registration_funding_derivation_path_for_chain(wallet.chain);
        path.base.base.wallet = Some(wallet);
        path
    }

    pub fn identity_topup_funding_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        let mut path = Self::identity_topup_funding_derivation_path_for_chain(wallet.chain);
        path.base.base.wallet = Some(wallet);
        path
    }

    pub fn identity_invitation_funding_derivation_path_for_wallet(wallet: &Wallet) -> Self {
        let mut path = Self::identity_invitation_funding_derivation_path_for_chain(wallet.chain);
        path.base.base.wallet = Some(wallet);
        path
    }
}
