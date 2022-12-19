use crate::crypto::primitives::utxo::UTXO;
use crate::keychain::keychain::IKeychainObject;

pub const IDENTITY_INDEX_KEY: &str = "IDENTITY_INDEX_KEY";
pub const IDENTITY_LOCKED_OUTPUT_KEY: &str = "IDENTITY_LOCKED_OUTPUT_KEY";

pub struct Identity {
    // pub index_key: &'static str,
    pub index: u32,
    // pub locked_outpoint_key: &'static str,
    pub locked_outpoint: Option<UTXO>,
    // (IDENTITY_INDEX_KEY.to_string(), identity_index_key),
    // (IDENTITY_LOCKED_OUTPUT_KEY.to_string(), unique_id_data)

}

impl dyn IKeychainObject<Identity> {
    fn from_keychain_data(data: &[u8]) -> Identity {

    }

    fn to_keychain_data(&self) -> &[u8] {
        todo!()
    }
}


