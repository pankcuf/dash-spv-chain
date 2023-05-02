use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use crate::crypto::UInt256;

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileRequestJson {
    #[serde(rename = "$createdAt")]
    pub created_at: NaiveDateTime,
    #[serde(rename = "$updatedAt")]
    pub updated_at: NaiveDateTime,
    #[serde(rename = "$revision")]
    pub revision: i32,
    #[serde(rename = "publicMessage")]
    pub public_message: Option<String>,
    #[serde(rename = "avatarUrl")]
    pub avatar_url: Option<String>,
    #[serde(rename = "avatarFingerprint")]
    pub avatar_fingerprint: Option<i64>,
    #[serde(rename = "avatarHash")]
    pub avatar_hash: Option<UInt256>,

    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}
