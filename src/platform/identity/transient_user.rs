#[derive(Debug, Default)]
pub struct TransientUser {
    pub display_name: Option<String>,
    pub avatar_path: Option<String>,
    pub avatar_fingerprint: Option<Vec<u8>>,
    pub avatar_hash: Option<Vec<u8>>,
    pub public_message: Option<String>,
    pub revision: u32,
    pub document_identifier: Vec<u8>,
    pub created_at: u64, //NSTimeInterval
    pub updated_at: u64, //NSTimeInterval
}
