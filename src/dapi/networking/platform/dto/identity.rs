use serde::{Deserialize, Serialize};
use crate::crypto::UInt256;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IdentityDTO {
    pub id: UInt256,
    pub balance: u64,
    #[serde(rename = "publicKeys")]
    pub public_keys: Vec<serde_json::Value>,
}
