use crate::chain::chain::Chain;

pub trait SerializableObject {
    fn chain(&self) -> &Chain;
    fn key_value_dictionary(&mut self) -> serde_json::Value;
    fn base_key_value_dictionary(&self) -> serde_json::Value;
    fn serialized(&mut self) -> Vec<u8>;
    fn serialized_base_data(&mut self) -> Vec<u8>;
    fn serialized_hash(&mut self) -> Vec<u8>;
    fn serialized_base_data_hash(&mut self) -> Vec<u8>;
    fn reset_serialized_values(&mut self);
}
