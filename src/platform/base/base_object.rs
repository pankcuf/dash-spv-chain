use hashes::{Hash, sha256d};
use crate::consensus::Encodable;
use crate::chain::chain::Chain;
use crate::platform::base::serializable_object::SerializableObject;


#[derive(Debug, Default)]
pub struct BaseObject {
    pub chain: &'static Chain,
    pub serialized: Option<Vec<u8>>,
    pub serialized_base_data: Option<Vec<u8>>,
    pub serialized_hash: Option<Vec<u8>>,
    pub serialized_base_data_hash: Option<Vec<u8>>,
    pub(crate) key_value_dictionary: Option<serde_json::Value>,
}

impl SerializableObject for BaseObject {
    fn chain(&self) -> &Chain {
        self.chain
    }

    fn key_value_dictionary(&mut self) -> serde_json::Value {
        panic!("Should be overriden in subclass");
    }

    fn base_key_value_dictionary(&self) -> serde_json::Value {
        todo!()
    }

    fn serialized(&mut self) -> Vec<u8> {
        if let Some(serialized) = &self.serialized {
            serialized.clone()
        } else {
            let offset: &mut usize = &mut 0;
            let mut buffer: Vec<u8> = Vec::new();
            *offset += self.chain.params.platform_protocol_version.enc(&mut buffer);
            // if let serde_json::Value::Object(map) = self.key_value_dictionary() {
                // TODO: minicbor::encode(data)
                // minicbor::Encoder
                // *offset += data.enc(&mut buffer);
            // }
            self.serialized = Some(buffer);
            buffer.clone()
        }
    }

    fn serialized_base_data(&mut self) -> Vec<u8> {
        if let Some(serialized) = &self.serialized_base_data {
            serialized.clone()
        } else {
            let mut buffer: Vec<u8> = Vec::new();
            self.chain.params.platform_protocol_version.enc(&mut buffer);
            // if let Some(data) = self.base_key_value_dictionary() {
            //     // TODO: minicbor::encode(data)
            //     data.enc(&mut buffer);
            // }
            self.serialized_base_data = Some(buffer);
            buffer.clone()
        }
    }

    fn serialized_hash(&mut self) -> Vec<u8> {
        if let Some(serialized) = &self.serialized_hash {
            serialized.clone()
        } else {
            let data = self.serialized();
            let hash = sha256d::Hash::hash(&data).into_inner().to_vec();
            self.serialized_hash = Some(hash);
            hash.clone()
        }
    }

    fn serialized_base_data_hash(&mut self) -> Vec<u8> {
        if let Some(serialized) = &self.serialized_base_data_hash {
            serialized.clone()
        } else {
            let data = self.serialized_base_data();
            let hash = sha256d::Hash::hash(&data).into_inner().to_vec();
            self.serialized_base_data_hash = Some(hash);
            hash.clone()
        }
    }

    fn reset_serialized_values(&mut self) {
        self.serialized = None;
        self.serialized_hash = None;
        self.serialized_base_data = None;
        self.serialized_base_data_hash = None;
    }
}
