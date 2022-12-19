use std::collections::HashMap;
use bitcoin_hashes::{Hash, sha256d};
use crate::crypto::byte_util::AsBytes;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::keys::key::IKey;
use crate::platform::base::base_object::BaseObject;
use crate::platform::identity::identity::Identity;
use crate::platform::transition::r#type::Type;
use crate::platform::transition::transition::{ITransition, Transition};

pub struct IdentityRegistrationTransition {
    pub base: Transition,
    public_keys: HashMap<u32, dyn IKey>,
    credit_funding_transaction: &'static CreditFundingTransaction,
}

impl IdentityRegistrationTransition {
    pub fn new(version: u16, public_keys: HashMap<u32, dyn IKey>, credit_funding_transaction: &CreditFundingTransaction, chain: &Chain) -> Self {
        assert!(!public_keys.is_empty(), "There must be at least one key when registering a user");
        Self {
            base: Transition {
                base: BaseObject { chain, ..Default::default() },
                version,
                identity_unique_id: UInt256::sha256d(credit_funding_transaction.locked_outpoint.as_bytes()),
                r#type: Type::IdentityRegistration,
                ..Default::default()
            },
            public_keys,
            credit_funding_transaction,
        }
    }
}

impl ITransition for IdentityRegistrationTransition {
    fn sign_with_key(&mut self, private_key: &dyn IKey, index: u32, identity: &Identity) {
        self.base.sign_with_key(private_key, index, identity)
    }
}

