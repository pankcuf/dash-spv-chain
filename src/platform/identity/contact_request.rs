use std::collections::HashMap;
use crate::crypto::UInt256;
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::platform::base::serializable_object::SerializableValue;
use crate::platform::identity::identity::Identity;
use crate::util::json::json_object::JsonObject;


#[derive(Debug, Serialize, Deserialize)]
pub struct ContactRequestJson {
    #[serde(rename = "toUserId")]
    pub recipient_identity_unique_id: UInt256,
    #[serde(rename = "$ownerId")]
    pub sender_identity_unique_id: UInt256,
    pub encrypted_account_label: Vec<u8>,
    #[serde(rename = "encryptedPublicKey")]
    pub encrypted_public_key_data: Vec<u8>,
    pub account_reference: u32,
    pub recipient_key_index: u32,
    pub sender_key_index: u32,
    #[serde(rename = "$createdAt")]
    pub created_at: u64,
}
impl JsonObject for ContactRequestJson {}

pub struct ContactRequest {
    pub identity: &'static Identity,
    pub raw_contact: &'static ContactRequestJson,
}

impl ContactRequest {

    pub fn contact_request_from_dictionary(raw_contact: &ContactRequestJson, identity: &Identity) -> Self {
        Self { identity, raw_contact }
    }

    pub fn identity_is_recipient(&self) -> bool {
        if self.identity.unique_id == self.raw_contact.recipient_identity_unique_id {
            // we are the recipient of the friend request
            true
        } else if self.identity.unique_id == self.raw_contact.sender_identity_unique_id {
            // we are the sender of the friend request
            false
        } else {
            assert!(false, "We should never get here");
            false
        }
    }

    pub fn secret_key_for_decryption_of_type(&self, r#type: &KeyType) -> &dyn IKey {
        let index = if self.identity_is_recipient() { self.raw_contact.recipient_key_index } else { self.raw_contact.sender_key_index };
        let key = self.identity.private_key_at_index(index, r#type);
        assert!(key.is_some(), "Key should exist");
        key.unwrap()
    }

    pub fn decrypted_public_key_data_with_key(&self, key: &dyn IKey) -> Vec<u8> {
        self.secret_key_for_decryption_of_type(key.r#type()).decrypt(&self.raw_contact.encrypted_public_key_data, key)
    }

}
