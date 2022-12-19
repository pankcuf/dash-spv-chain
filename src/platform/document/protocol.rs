use std::collections::HashMap;
use crate::crypto::UInt256;
use crate::platform::base::serializable_object::{SerializableKey, SerializableObject, SerializableValue};
use crate::platform::document::Document;
use crate::platform::document::factory::TableName;
use crate::util;

pub enum TableName {
    Domain,
    Profile,
    ContactRequest,
}

impl SerializableKey for TableName {
    fn as_str(&self) -> &str {
        match self {
            TableName::Domain => "domain",
            TableName::Profile => "profile",
            TableName::ContactRequest => "contactRequest",
        }
    }
}

pub trait Protocol {
    fn document_on_table_using_entropy(&self, table_name: TableName, data_dictionary: Option<HashMap<dyn SerializableKey, dyn SerializableValue>>, entropy: &UInt256) -> Result<Document, util::Error>;
    fn document_on_table_using_document_identifier(&self, table_name: TableName, data_dictionary: Option<HashMap<dyn SerializableKey, dyn SerializableValue>>, identifier: &UInt256) -> Result<Document, util::Error>;

}
