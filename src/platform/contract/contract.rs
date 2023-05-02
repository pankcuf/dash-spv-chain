use std::borrow::Borrow;
use diesel::QueryResult;
use hashes::{Hash, sha256d};
use hashes::hex::ToHex;
use crate::chain::chain::Chain;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, Zeroable};
use crate::crypto::UInt256;
use crate::derivation::authentication_keys_derivation_path::AuthenticationKeysDerivationPath;
use crate::derivation::simple_indexed_derivation_path::ISimpleIndexedDerivationPath;
use crate::platform::base::base_object::BaseObject;
use crate::platform::base::serializable_object::SerializableObject;
use crate::platform::contract::{ContractState, ContractType};
use crate::platform::identity::identity::Identity;
use crate::platform::platform::Platform;
use crate::platform::transition::contract_transition::ContractTransition;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::common::contract::ContractEntity;
use crate::util::base58;

pub const DEFAULT_VERSION: i64 = 1;
pub const DEFAULT_SCHEMA: &str = "https://schema.dash.org/dpp-0-4-0/meta/data-contract";
pub const DPCONTRACT_SCHEMA_ID: &str = "contract";

#[derive(Debug, Default)]
pub struct Contract {
    pub base: BaseObject,
    pub local_contract_identifier: String,
    pub name: String,
    pub base58_contract_id: String,
    pub base58_owner_id: String,
    pub status_string: String,
    pub json_schema_id: String,
    pub json_meta_schema: String,
    pub registered_identity_unique_id: UInt256,
    pub contract_id: UInt256,
    pub entropy: UInt256,
    pub version: i64,
    //
    // pub object_dictionary: HashMap<String, dyn SerializableValue>,
    // pub documents: HashMap<String, HashMap<String, dyn SerializableValue>>,
    // pub definitions: HashMap<String, HashMap<String, dyn SerializableValue>>,

    pub documents: serde_json::Value,
    pub definitions: serde_json::Value,
    pub state: ContractState,
}

impl Contract {

    pub fn has_registered_identity(&self) -> bool {
        !self.registered_identity_unique_id.is_zero()
    }

    pub fn with_local_contract_identifier(local_contract_identifier: String, documents: serde_json::Value, chain: &Chain) -> Self {
        Self {
            base: BaseObject { chain, ..Default::default() },
            version: DEFAULT_VERSION,
            local_contract_identifier,
            documents,
            json_meta_schema: DEFAULT_SCHEMA.to_string(),
            definitions: serde_json::Value::Array(vec![]),
            ..Default::default()
        }
    }

    pub fn with_name(name: String, local_identifier: String, documents: serde_json::Value, chain: &Chain) -> Option<Self> {
        Self::from(
            serde_json::Value::Object(
                serde_json::Map::from_iter([
                    ("name".to_owned(), serde_json::Value::String(name)),
                    ("documents".to_owned(), documents)])),
            local_identifier,
            chain)
    }

    pub fn from(raw_contract: serde_json::Value, local_identifier: String, chain: &Chain) -> Option<Self> {
        if let Some(&documents) = raw_contract.get("documents") {
            let mut contract = Contract::with_local_contract_identifier(local_identifier, documents, chain);
            if let Some(&value) = raw_contract.get("$schema") {
                contract.json_meta_schema = serde_json::from_value::<String>(value).unwrap();
            }
            if let Some(&value) = raw_contract.get("version") {
                contract.version = serde_json::from_value::<i64>(value).unwrap();
            }
            if let Some(&value) = raw_contract.get("definitions") {
                contract.definitions = value;
            }
            Some(contract)
        } else {
            None
        }
    }

    /// Contract Info
    pub fn contract_id(&mut self) -> &UInt256 {
        if self.contract_id.is_zero() {
            assert!(!self.registered_identity_unique_id.is_zero(), "Registered Identity needs to be set");
            assert!(!self.entropy.is_zero(), "Entropy needs to be set");
            let mut writer = &mut Vec::<u8>::new();
            self.registered_identity_unique_id.enc(writer);
            self.entropy.enc(writer);
            self.contract_id = UInt256::sha256d(&writer);
        }
        &self.contract_id
    }

    pub fn contract_id_if_registered_by_identity(&mut self, identity: &Identity) -> UInt256 {
        let mut writer = &mut Vec::<u8>::new();
        identity.unique_id.enc(writer);
        if let Some(wallet) = identity.wallet {
            let mut derivation_path = AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_wallet(wallet);
            let mut entropy_data = &mut self.serialized_hash().clone();
            identity.unique_id.enc(entropy_data);
            // use the last key in 32 bit space (it won't probably ever be used anyways)
            if let Some(pk_data) = derivation_path.public_key_data_at_index(u32::MAX - 1) {
                pk_data.enc(entropy_data);
            }
            UInt256::sha256(&entropy_data).enc(writer);
        }
        // this is the contract ID
        UInt256::sha256d(writer)
    }

    pub fn base58_contract_id(&self) -> String {
        base58::encode_slice(self.contract_id.as_bytes())
    }

    pub fn base58_owner_id(&self) -> String {
        assert!(!self.registered_identity_unique_id.is_zero(), "Registered Identity can not be 0");
        base58::encode_slice(self.registered_identity_unique_id.as_bytes())
    }

    pub fn local_contract_identifier(&mut self) -> &String {
        if self.local_contract_identifier.is_empty() {
            self.local_contract_identifier = format!("{}-{}", base58::encode_slice(sha256d::Hash::hash(&self.serialized()).borrow()), self.chain().unique_id);
        }
        &self.local_contract_identifier
    }
    pub fn json_schema_id(&self) -> String {
        DPCONTRACT_SCHEMA_ID.to_string()
    }

    pub fn set_version(&mut self, version: i64) {
        self.version = version;
        self.base.reset_serialized_values();
    }

    pub fn set_json_meta_schema(&mut self, json_meta_schema: String) {
        self.json_meta_schema = json_meta_schema;
        self.base.reset_serialized_values();
    }

    pub fn documents(&self) -> serde_json::Value {
        self.documents.clone()
    }

    pub fn set_documents(&mut self, documents: serde_json::Value) {
        self.documents = documents.clone();
        self.base.reset_serialized_values();
    }

    pub fn set_definitions(&mut self, definitions: serde_json::Value) {
        self.definitions = definitions.clone();
        self.base.reset_serialized_values();
    }

    pub fn is_document_defined_for_type(&self, r#type: ContractType) -> bool {
        self.documents.get(r#type.name()).is_some()
    }

    pub fn set_document_schema(&mut self, schema: serde_json::Value, r#type: ContractType) {
        self.documents = match &self.documents {
            serde_json::Value::Object(map) => {
                let mut m = map.clone();
                m.insert(r#type.name().to_string(), schema);
                serde_json::Value::Object(m)
            },
            v => v.clone()
        };
    }

    pub fn document_schema_for_type(&self, r#type: ContractType) -> Option<&serde_json::Value> {
        self.documents.get(r#type.name())
    }

    pub fn document_schema_ref_for_type(&self, r#type: ContractType) -> Option<serde_json::Value> {
        if self.is_document_defined_for_type(r#type) {
            Some(serde_json::Value::Object(serde_json::Map::from_iter([("$ref".to_owned(), serde_json::Value::String(format!("{}#/documents/{}", self.json_schema_id(), r#type.name())))])))
        } else {
            None
        }
    }

    pub fn name(&self) -> String {
        Platform::name_for_contract_with_identifier(&self.local_contract_identifier)
    }

    pub fn status_string(&self) -> String {
        self.state.name().to_string()
    }

    pub fn unregister_creator_in_context(&mut self, context: &ManagedContext) {
        self.registered_identity_unique_id = UInt256::MIN;
        self.contract_id = UInt256::MIN;
        self.entropy = UInt256::MIN;
        self.save_and_wait_in_context(context);
    }

    pub fn register_creator(&mut self, identity: Option<&Identity>, context: &ManagedContext) {
        self.contract_id = UInt256::MIN;
        if let Some(identity) = identity {
            self.registered_identity_unique_id = identity.unique_id;
            if let Some(wallet) = identity.wallet {
                let mut entropy_data = &mut Vec::<u8>::new();
                identity.unique_id.enc(entropy_data);
                // use the last key in 32 bit space (it won't probably ever be used anyways)
                if let Some(pk_data) = AuthenticationKeysDerivationPath::identity_ecdsa_keys_derivation_path_for_wallet(wallet).public_key_data_at_index(u32::MAX - 1) {
                    pk_data.enc(entropy_data);
                }
                self.entropy = UInt256::sha256(entropy_data);
            }
        } else {
            self.registered_identity_unique_id = UInt256::MIN;
        }
        self.save_and_wait_in_context(context);
    }

    pub fn set_contract_state(&mut self, state: ContractState, context: &ManagedContext) {
        self.state = state;
        self.save_and_wait_in_context(context);
    }

    /// Transitions
    pub fn contract_registration_transition_for_identity(&self, identity: &Identity) -> ContractTransition {
        ContractTransition::new(self, 1, identity.unique_id, self.chain())
    }

    /// Saving
    pub fn contract_entity_in_context(&self, context: &ManagedContext) -> QueryResult<ContractEntity> {
        ContractEntity::get_by_local_identifier(&self.local_contract_identifier, self.chain().r#type(), context)
    }

    pub fn save_and_wait_in_context(&self, context: &ManagedContext) {
        // TODO: impl update_or_create
        context.perform_block_and_wait(|context| {
            // if let Some(entity) = self.contract_entity_in_context(context) {
            //
            // } else if let Some(entity) = ContractEntity::create_and_get(self, context) {
            //
            // }
            // let mut has_change = false;
            // if (!entity) {
            //     entity = [DSContractEntity managedObjectInBlockedContext:context];
            //     entity.chain = [self.chain chainEntityInContext:context];
            //     entity.localContractIdentifier = self.localContractIdentifier;
            //     if (uint256_is_not_zero(self.registeredBlockchainIdentityUniqueID)) {
            //         entity.registeredBlockchainIdentityUniqueID = uint256_data(self.registeredBlockchainIdentityUniqueID);
            //     }
            //     if (uint256_is_not_zero(self.entropy)) {
            //         entity.entropy = uint256_data(self.entropy);
            //     }
            //     hasChange = YES;
            // }
            // if (uint256_is_not_zero(self.registeredBlockchainIdentityUniqueID) && (!entity.registeredBlockchainIdentityUniqueID || !uint256_eq(entity.registeredBlockchainIdentityUniqueID.UInt256, self.registeredBlockchainIdentityUniqueID))) {
            //     entity.registeredBlockchainIdentityUniqueID = uint256_data(self.registeredBlockchainIdentityUniqueID);
            //     hasChange = YES;
            // } else if (uint256_is_zero(self.registeredBlockchainIdentityUniqueID) && entity.registeredBlockchainIdentityUniqueID) {
            //     entity.registeredBlockchainIdentityUniqueID = nil;
            //     hasChange = YES;
            // }
            //
            // if (uint256_is_not_zero(self.entropy) && (!entity.entropy || !uint256_eq(entity.entropy.UInt256, self.entropy))) {
            //     entity.entropy = uint256_data(self.entropy);
            //     hasChange = YES;
            // } else if (uint256_is_zero(self.entropy) && entity.entropy) {
            //     entity.entropy = nil;
            //     hasChange = YES;
            // }
            //
            // if (entity.state != self.contractState) {
            //     entity.state = self.contractState;
            //     hasChange = YES;
            // }
            //
            // if (hasChange) {
            //     [context ds_save];
            //     dispatch_async(dispatch_get_main_queue(), ^{
            //         [[NSNotificationCenter defaultCenter] postNotificationName:DPContractDidUpdateNotification object:nil userInfo:@{DSContractUpdateNotificationKey: self}];
            //     });
            // }
        });

    }

    /// Special Contracts
    pub fn contract_of_type(r#type: ContractType, chain: &Chain) -> Self {
        Self::contract_at_path(r#type, r#type.into(), chain)
    }

    pub fn contract_at_path(r#type: ContractType, identifier: String, chain: &Chain) -> Self {
        // TODO: read async'ly
        let raw_contract = chain.environment.resource_bundle.load_contract_scheme(r#type);
        let local_identifier = format!("{}-{}", identifier, chain.unique_id);
        let contract = Self::from(raw_contract, local_identifier, chain);
        assert!(contract.is_some(), "Failed building Contract");
        contract.unwrap()
    }

    pub fn local_dashpay_contract_for_chain(chain: &Chain) -> Self {
        let mut contract = Self::contract_of_type(ContractType::DashPay, chain);
        if !chain.params.dashpay_contract_id.is_zero() && contract.state == ContractState::Unknown {
            contract.set_contract_state(ContractState::Registered, chain.platform_context());
            contract.contract_id = chain.params.dashpay_contract_id.clone();
            contract.save_and_wait_in_context(chain.platform_context());
        }
        contract
    }

    pub fn local_dpns_contract_for_chain(chain: &Chain) -> Self {
        let mut contract = Self::contract_of_type(ContractType::DPNS, chain);
        if !chain.params.dpns_contract_id.is_zero() && contract.state == ContractState::Unknown {
            contract.set_contract_state(ContractState::Registered, chain.platform_context());
            contract.contract_id = chain.params.dpns_contract_id.clone();
            contract.save_and_wait_in_context(chain.platform_context());
        }
        contract
    }
    pub fn local_dash_thumbnail_contract_for_chain(chain: &Chain) -> Self {
        Self::contract_of_type(ContractType::DashThumbnail, chain)
    }




    pub(crate) fn documents_keys(&self) -> serde_json::Map<String, serde_json::Value> {
        match &self.documents {
            serde_json::Value::Object(map) => map.clone(),
            _ => serde_json::Map::default()
        }
    }

    pub fn object_dictionary(&mut self) -> serde_json::Value {
        self.base.key_value_dictionary.unwrap_or({
            let mut map = serde_json::Map::from_iter([
                ("$schema".to_owned(), serde_json::Value::String(self.json_meta_schema.clone())),
                ("ownerId".to_owned(), serde_json::Value::String(self.registered_identity_unique_id.0.to_hex())),
                ("$id".to_owned(), serde_json::Value::String(self.contract_id().0.to_hex())),
                ("documents".to_owned(), self.documents()),
                ("protocolVersion".to_owned(), serde_json::Value::Number(serde_json::Number::from(0))),
            ]);
            if let serde_json::Value::Array(arr) = &self.definitions {
                if !arr.is_empty() {
                    map.insert("definitions".to_owned(), serde_json::Value::Array(arr.clone()));
                }
            }
            let value = serde_json::Value::Object(map);
            self.base.key_value_dictionary = Some(value.clone());
            value
        })
    }

}

impl SerializableObject for Contract {
    fn chain(&self) -> &Chain {
        self.base.chain()
    }

    fn key_value_dictionary(&mut self) -> serde_json::Value {
        self.base.key_value_dictionary()
    }

    fn base_key_value_dictionary(&self) -> serde_json::Value {
        self.base.base_key_value_dictionary()
    }

    fn serialized(&mut self) -> Vec<u8> {
       self.base.serialized()
    }

    fn serialized_base_data(&mut self) -> Vec<u8> {
        self.base.serialized_base_data()
    }

    fn serialized_hash(&mut self) -> Vec<u8> {
        self.base.serialized()
    }

    fn serialized_base_data_hash(&mut self) -> Vec<u8> {
        self.base.serialized_base_data_hash()
    }

    fn reset_serialized_values(&mut self) {
        self.base.reset_serialized_values();
        self.base.key_value_dictionary = None;
    }
}
