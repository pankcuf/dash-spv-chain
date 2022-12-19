use std::collections::HashMap;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::dapi::platform_query::PlatformQuery;
use crate::keys::key::IKey;
use crate::platform::base::serializable_object::{SerializableKey, SerializableObject, SerializableValue};
use crate::platform::document::Document;
use crate::platform::document::document::{DocumentKey, DocumentValue};
use crate::platform::identity::identity::Identity;
use crate::platform::transition::r#type::Type;
use crate::platform::transition::transition::{ITransition, Transition, TransitionValue};

pub enum DocumentTransitionKey {
    Transitions,
    OwnerId
}

impl SerializableKey for DocumentTransitionKey {
    fn as_str(&self) -> &str {
        match self {
            DocumentTransitionKey::Transitions => "transitions",
            DocumentTransitionKey::OwnerId => "ownerId",
        }
    }
}

pub struct DocumentTransition {
    pub base: Transition,
    pub documents: Vec<Document>,
    pub expected_response_query: PlatformQuery,
    actions: Vec<u32>,
}

impl ITransition for DocumentTransition {
    fn sign_with_key(&mut self, private_key: &dyn IKey, index: u32, identity: &Identity) {
        self.base.sign_with_key(private_key, index, identity)
    }
}

impl SerializableObject for DocumentTransition {
    fn chain(&self) -> &Chain {
        self.base.chain()
    }

    fn key_value_dictionary(&mut self) -> &HashMap<dyn SerializableKey, dyn SerializableValue> {
        self.base.key_value_dictionary()
    }

    fn base_key_value_dictionary(&self) -> &HashMap<dyn SerializableKey, dyn SerializableValue> {
        let mut json = self.base.base_key_value_dictionary();
        json.insert(DocumentTransitionKey::Transitions, TransitionValue::ArrayOfDictionaries(&self.documents_as_array_of_dictionaries()));
        json.insert(DocumentTransitionKey::OwnerId, TransitionValue::Uint256(&self.base.identity_unique_id));
        &json
    }

    fn serialized(&mut self) -> Vec<u8> {
        self.base.serialized()
    }

    fn serialized_base_data(&mut self) -> Vec<u8> {
        self.base.serialized_base_data()
    }

    fn serialized_hash(&mut self) -> Vec<u8> {
        self.base.serialized_hash()
    }

    fn serialized_base_data_hash(&mut self) -> Vec<u8> {
        self.base.serialized_base_data_hash()
    }
}

impl DocumentTransition {

    pub fn init_for_documents(documents: Vec<Document>, version: u16, identity_unique_id: UInt256, chain: &Chain) -> Self {
        let mut b = Transition::init_with_transition_version(version, identity_unique_id, chain);
        b.r#type = Type::Documents;
        Self {
            base: b,
            documents,
            expected_response_query: PlatformQuery {},
            actions: vec![]
        }
    }

    fn documents_as_array_of_dictionaries(&self) -> Vec<HashMap<DocumentKey, DocumentValue>> {
        self.documents.iter().map(|document| document.object_dictionary()).collect()
    }




}
