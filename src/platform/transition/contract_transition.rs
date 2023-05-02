use crate::chain::chain::Chain;
use crate::crypto::UInt256;
use crate::keys::key::IKey;
use crate::platform::contract::contract::Contract;
use crate::platform::identity::identity::Identity;
use crate::platform::transition;
use crate::platform::transition::transition::{ITransition, Transition};

pub struct ContractTransition {
    pub base: Transition,
    pub contract: &'static Contract,
}

impl ITransition for ContractTransition {
    fn sign_with_key(&mut self, private_key: &dyn IKey, index: u32, identity: &Identity) {
        self.base.sign_with_key(private_key, index, identity);
    }
}

impl ContractTransition {

    pub fn new(contract: &Contract, transition_version: u16, identity_unique_id: UInt256, chain: &Chain) -> Self {
        Self {
            base: Transition::init_of_type_with_transition_version(transition::Type::DataContract, transition_version, identity_unique_id, chain),
            contract
        }
    }

}
