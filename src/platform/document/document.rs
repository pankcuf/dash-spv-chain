use std::collections::HashMap;
use crate::crypto::UInt256;
use crate::platform::base::serializable_object::{SerializableKey, SerializableValue};
use crate::platform::contract::document_type::DocumentType;
use crate::platform::document;
use crate::platform::transition::transition::TransitionValue;

pub enum DocumentKey {
    Id,
    Type,
    Action,
    Entropy,
    DataContractId,
    UpdatedAt
}

impl SerializableKey for DocumentKey {
    fn as_str(&self) -> &str {
        match self {
            DocumentKey::Id => "$id",
            DocumentKey::Type => "$type",
            DocumentKey::Action => "$action",
            DocumentKey::Entropy => "$entropy",
            DocumentKey::DataContractId => "$dataContractId",
            DocumentKey::UpdatedAt => "$updatedAt",

        }
    }
}

pub enum DocumentValue {
    TableName(&'static String),
    UInt256(&'static UInt256),
    Bytes(&'static Vec<u8>),
}

impl SerializableValue for DocumentValue {}

pub struct Document {

    pub document_type: DocumentType,
    pub table_name: String,
    pub owner_id: UInt256,
    pub base58OwnerIdString: String,
    pub contract_id: UInt256,
    pub base58ContractIdString: String,
    pub document_id: UInt256,
    pub base58DocumentIdString: String,
    pub entropy: Vec<u8>,
    pub current_registered_document_state: document::State,
    pub current_local_document_state: document::State,

    pub current_registered_revision: u32,
    pub current_local_revision: u32,

    pub object_dictionary: HashMap<DocumentKey, DocumentValue>,
    pub main_index_key: Vec<u8>,


}

impl Document {
    pub fn object_dictionary(&self) -> HashMap<DocumentKey, DocumentValue> {
        let state_type: u32 = &self.current_local_document_state.document_state_type.into();
        let mut json = HashMap::<DocumentKey, DocumentValue>::new();
        json.insert(DocumentKey::Type, DocumentValue::TableName(&self.table_name));
        json.insert(DocumentKey::DataContractId, DocumentValue::UInt256(&self.document_id));
        json.insert(DocumentKey::Action, TransitionValue::U32(&self.current_local_document_state.document_state_type.into() >> 1))


        json[@"$action"] = @(self.current_local_document_state.document_state_type >> 1);
        if (!(self.current_local_document_state.documentStateType >> 1)) {
            json.insert(DocumentKey::Entropy, DocumentValue::Bytes(&self.entropy));
        }
        json.extend(&self.current_local_document_state.data_change_dictionary);

        [json addEntriesFromDictionary:self.cu.dataChangeDictionary];
        json
    }


}
