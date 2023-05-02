use hashes::hex::ToHex;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, Zeroable};
use crate::crypto::UInt256;
use crate::platform::contract::document_type::DocumentType;
use crate::platform::document;
use crate::util::base58;

pub enum DocumentKey {
    Id,
    Type,
    Action,
    Entropy,
    DataContractId,
    UpdatedAt
}

// impl SerializableKey for DocumentKey {
//     fn as_str(&self) -> &str {
//         match self {
//             DocumentKey::Id => "$id",
//             DocumentKey::Type => "$type",
//             DocumentKey::Action => "$action",
//             DocumentKey::Entropy => "$entropy",
//             DocumentKey::DataContractId => "$dataContractId",
//             DocumentKey::UpdatedAt => "$updatedAt",
//
//         }
//     }
// }

pub enum DocumentValue {
    TableName(&'static String),
    UInt256(&'static UInt256),
    Bytes(&'static Vec<u8>),
}

#[derive(Debug, Default)]
pub struct Document {

    pub document_type: DocumentType,
    pub table_name: String,
    pub owner_id: UInt256,
    pub contract_id: UInt256,

    document_id: UInt256,
    base58_owner_id_string: Option<String>,
    base58_contract_id_string: Option<String>,
    base58_document_id_string: Option<String>,

    pub entropy: Vec<u8>,
    pub current_registered_document_state: document::State,
    pub current_local_document_state: document::State,

    pub current_registered_revision: u32,
    pub current_local_revision: u32,

    pub object_dictionary: serde_json::Value,
    pub main_index_key: Vec<u8>,
}

impl Document {
    pub fn document_id(&mut self) -> UInt256 {
        if self.document_id.is_zero() {
            assert!(!self.owner_id.is_zero(), "Owner needs to be set");
            assert!(!self.contract_id.is_zero(), "Contract needs to be set");
            assert!(!self.table_name.is_empty(), "Table name needs to be set");
            let mut writer = &mut Vec::<u8>::new();
            self.contract_id.enc(writer);
            self.owner_id.enc(writer);
            // TOdo: it also write varint. should we?
            self.table_name.enc(writer);
            self.entropy.enc(writer);
            self.document_id = UInt256::sha256d(writer);
        }
        self.document_id
    }

    fn base58_owner_id_string(&mut self) -> String {
        if self.base58_owner_id_string.is_none() && !self.owner_id.is_zero() {
            self.base58_owner_id_string = Some(base58::encode_slice(self.owner_id.as_bytes()))
        }
        self.base58_owner_id_string.expect("owner_id should be set")
    }

    fn base58_contract_id_string(&mut self) -> String {
        if self.base58_contract_id_string.is_none() && !self.contract_id.is_zero() {
            self.base58_contract_id_string = Some(base58::encode_slice(self.contract_id.as_bytes()))
        }
        self.base58_contract_id_string.expect("contract_id should be set")
    }

    fn base58_document_id_string(&mut self) -> String {
        if self.base58_document_id_string.is_none() {
            self.base58_document_id_string = Some(base58::encode_slice(self.document_id.as_bytes()))
        }
        self.base58_contract_id_string.unwrap()
    }
}


impl Document {
    pub fn object_dictionary(&self) -> serde_json::Value {
        let state_type: u32 = self.current_local_document_state.document_state_type.into();
        let state_type_new: u32 = state_type >> 1;
        let mut map = serde_json::Map::from_iter([
            ("$type".to_owned(), serde_json::Value::String(self.table_name.clone())),
            ("$dataContractId".to_owned(), serde_json::Value::String(self.document_id.0.to_hex())),
            ("$action".to_owned(), serde_json::Value::Number(serde_json::Number::from(state_type))),
        ]);
        if state_type == 0 {
            map.insert("$entropy".to_owned(), serde_json::Value::String(self.entropy.to_hex()));
        }
        let mut json = serde_json::Value::Object(map);
        crate::util::json::merge(&mut json, self.current_registered_document_state.data_change_dictionary.clone());
        json
    }
}
