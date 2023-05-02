use serde::{Deserialize, Serialize};
use crate::crypto::UInt256;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PreorderRequest {
    #[serde(rename = "saltedDomainHash")]
    pub salted_domain_hash: UInt256,
}
