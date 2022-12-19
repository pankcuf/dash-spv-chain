use std::collections::HashSet;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::derivation::derivation_path::{DerivationPath, DerivationPathKind, IDerivationPath};
use crate::derivation::derivation_path_feature_purpose::DerivationPathFeaturePurpose;
use crate::derivation::derivation_path_reference::DerivationPathReference;
use crate::derivation::derivation_path_type::DerivationPathType;
use crate::derivation::simple_indexed_derivation_path::{ISimpleIndexedDerivationPath, SimpleIndexedDerivationPath};
use crate::derivation::uint256_index_path::{IIndexPath, IndexPath};
use crate::keys::key::IKey;
use crate::keys::KeyType;

pub struct CreditFundingDerivationPath {
    pub base: SimpleIndexedDerivationPath,
}

impl IDerivationPath for CreditFundingDerivationPath {
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

    fn standalone_extended_public_key_unique_id(&mut self) -> Option<String> {
        self.base.standalone_extended_public_key_unique_id()
    }

    fn kind(&self) -> DerivationPathKind {
        DerivationPathKind::CreditFunding
    }

    fn balance(&self) -> u64 {
        self.base.balance()
    }

    fn public_key_at_index_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        todo!()
    }

    fn base_index_path<T>(&self) -> IndexPath<T> {
        todo!()
    }
}

impl ISimpleIndexedDerivationPath for CreditFundingDerivationPath {
    fn addresses_to_index(&self, index: u32) -> HashSet<String> {
        todo!()
    }

    fn addresses_to_index_using_cache(&self, index: u32, use_cache: bool, add_to_cache: bool) -> HashSet<String> {
        todo!()
    }

    fn address_at_index(&self, index: u32) -> Option<String> {
        todo!()
    }

    fn address_is_used_at_index(&self, index: u32) -> bool {
        todo!()
    }

    fn index_path_of_known_address(&self, address: String) -> Option<dyn IIndexPath> {
        todo!()
    }

    fn index_of_known_address(&self, address: Option<String>) -> Option<u32> {
        todo!()
    }

    fn public_key_data_at_index(&self, index: u32) -> Option<Vec<u8>> {
        todo!()
    }
}

impl CreditFundingDerivationPath {
    pub fn generate_extended_public_key_from_seed(&mut self, seed: &Vec<u8>, wallet_unique_id: Option<&String>) -> Option<&dyn IKey> {
        self.base.base.generate_extended_public_key_from_seed_and_store_private_key(seed, wallet_unique_id, false)
    }

    fn blockchain_identity_funding_derivation_path_for_chain(reference: DerivationPathReference, last_index: u32, chain: &Chain) -> Self {
        Self {
            base: SimpleIndexedDerivationPath {
                base: DerivationPath::derivation_path_with_indexes(
                    vec![
                        UInt256::from_u32(DerivationPathFeaturePurpose::DEFAULT.into()),
                        UInt256::from_u32(chain.params.chain_type.coin_type()),
                        UInt256::from_u32(DerivationPathFeaturePurpose::IDENTITIES.into()),
                        UInt256::from_u32(last_index),
                    ],
                    vec![true, true, true, true],
                    DerivationPathType::CreditFunding,
                    KeyType::ECDSA,
                    reference,
                    chain
                )
            },
            ..Default::default()
        }
    }

    pub fn identity_registration_funding_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::blockchain_identity_funding_derivation_path_for_chain(
            DerivationPathReference::BlockchainIdentityCreditRegistrationFunding,
            DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_REGISTRATION.into(),
            chain
        )
    }

    pub fn identity_topup_funding_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::blockchain_identity_funding_derivation_path_for_chain(
            DerivationPathReference::BlockchainIdentityCreditTopupFunding,
            DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_TOPUP.into(),
            chain
        )
    }

    pub fn identity_invitation_funding_derivation_path_for_chain(chain: &Chain) -> Self {
        Self::blockchain_identity_funding_derivation_path_for_chain(
            DerivationPathReference::BlockchainIdentityCreditInvitationFunding,
            DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_INVITATIONS.into(),
            chain
        )
    }

}
