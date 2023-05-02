use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::platform::contract::contract::Contract;
use crate::platform::document::Document;
use crate::platform::document::protocol::{Protocol, TableName};
use crate::platform::identity::identity::Identity;
use crate::util;


#[derive(Debug, Default)]
pub struct Factory {
    pub user_id: UInt256,
    pub contract: &'static Contract,
    pub chain: &'static Chain
}

impl Factory {
    pub fn new(identity: &Identity, contract: &Contract, chain: &Chain) -> Self {
        Factory {
            user_id: identity.unique_id.clone(),
            contract,
            chain
        }
    }
}

impl Protocol for Factory {

    fn document_on_table_using_entropy(&self, table_name: TableName, data_dictionary: serde_json::Value, entropy: &UInt256) -> Result<Document, util::Error> {
        todo!()
    }

    fn document_on_table_using_document_identifier(&self, table_name: TableName, data_dictionary: serde_json::Value, identifier: &UInt256) -> Result<Document, util::Error> {
        todo!()
    }
 }
