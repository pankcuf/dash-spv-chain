use crate::crypto::UInt256;
use crate::platform::document::Document;
use crate::util;

pub enum TableName {
    Domain,
    Profile,
    Preorder,
    ContactRequest,
}

// impl SerializableKey for TableName {
//     fn as_str(&self) -> &str {
//         match self {
//             TableName::Domain => "domain",
//             TableName::Preorder => "preorder",
//             TableName::Profile => "profile",
//             TableName::ContactRequest => "contactRequest",
//         }
//     }
// }

pub trait Protocol {
    fn document_on_table_using_entropy(&self, table_name: TableName, data_dictionary: serde_json::Value, entropy: &UInt256) -> Result<Document, util::Error>;
    fn document_on_table_using_document_identifier(&self, table_name: TableName, data_dictionary: serde_json::Value, identifier: &UInt256) -> Result<Document, util::Error>;

}
