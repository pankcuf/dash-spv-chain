use serde::{Deserialize, Serialize};
use crate::crypto::UInt256;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ContractInfo {
    pub id: Option<UInt256>,
    pub documents: serde_json::Value,
}
