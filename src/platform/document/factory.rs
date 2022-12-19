use std::collections::HashMap;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::platform::base::serializable_object::{SerializableKey, SerializableValue};
use crate::platform::contract::contract::Contract;
use crate::platform::document::Document;
use crate::platform::document::protocol::{Error, Protocol, TableName};
use crate::platform::identity::identity::Identity;


pub struct Factory {
    pub user_id: &'static UInt256,
    pub contract: &'static Contract,
    pub chain: &'static Chain
}

impl Factory {
    pub fn new(identity: &Identity, contract: &Contract, chain: &Chain) -> Self {
        Factory {
            user_id: &identity.unique_id,
            contract,
            chain
        }
    }
}

impl Protocol for Factory {

    fn document_on_table_using_entropy(&self, table_name: TableName, data_dictionary: Option<HashMap<dyn SerializableKey, dyn SerializableValue>>, entropy: &UInt256) -> Result<Document, Error> {
        todo!()
    }

    fn document_on_table_using_document_identifier(&self, table_name: TableName, data_dictionary: Option<HashMap<dyn SerializableKey, dyn SerializableValue>>, identifier: &UInt256) -> Result<Document, Error> {
        todo!()
    }
 }
