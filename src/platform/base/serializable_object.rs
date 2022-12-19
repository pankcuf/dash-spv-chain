use std::collections::HashMap;
use crate::crypto::byte_util::AsBytes;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;

pub trait SerializableKey {
    fn as_str(&self) -> &str;
}

pub trait SerializableValue {
    fn as_data(&self) -> &[u8];
}

impl SerializableValue for String {
    fn as_data(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl SerializableValue for UInt256 {
    fn as_data(&self) -> &[u8] {
        self.as_bytes()
    }
}

pub trait SerializableObject {
    fn chain(&self) -> &Chain;
    fn key_value_dictionary(&self) -> &HashMap<dyn SerializableKey, dyn SerializableValue>;
    fn base_key_value_dictionary(&self) -> &HashMap<dyn SerializableKey, dyn SerializableValue>;
    fn serialized(&self) -> Vec<u8>;
    fn serialized_base_data(&self) -> Vec<u8>;
    fn serialized_hash(&self) -> Vec<u8>;
    fn serialized_base_data_hash(&self) -> Vec<u8>;
}
