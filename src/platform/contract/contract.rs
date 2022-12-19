use std::collections::HashMap;
use crate::crypto::byte_util::AsBytes;
use crate::crypto::UInt256;
use crate::platform::base::base_object::BaseObject;
use crate::platform::base::serializable_object::SerializableValue;
use crate::platform::contract::contract_state::ContractState;
use crate::platform::identity::identity::Identity;
use crate::platform::transition::contract_transition::ContractTransition;
use crate::storage::manager::managed_context::ManagedContext;

#[derive(Debug)]
pub struct Contract {
    pub base: BaseObject,
    pub local_contract_identifier: String,
    pub name: String,
    pub base58_contract_id: String,
    pub base58_owner_id: String,
    pub status_string: String,
    pub json_schema_id: String,
    pub json_meta_schema: String,
    pub registered_blockchain_identity_unique_id: UInt256,
    pub contract_id: UInt256,
    pub entropy: UInt256,
    pub version: i64,

    pub object_dictionary: HashMap<String, dyn SerializableValue>,
    pub documents: HashMap<String, HashMap<String, dyn SerializableValue>>,
    pub definitions: HashMap<String, HashMap<String, dyn SerializableValue>>,

    pub state: ContractState,
}

impl Contract {
    pub fn contract_id_bytes(&self) -> &Vec<u8> {
        &self.contract_id.as_bytes().to_vec()
    }

    pub(crate) fn contract_registration_transition_for_identity(&self, identity: &Identity) -> ContractTransition {
        ContractTransition::new(self, 1, identity.unique_id, self.base.chain)
    }

    pub(crate) fn register_creator(&self, identity: &Identity, context: &ManagedContext) {
        todo!()
    }
}
