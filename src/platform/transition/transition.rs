use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use bitcoin_hashes::{Hash, sha256};
use crate::crypto::byte_util::Zeroable;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::keys::bls_key::BLSKey;
use crate::keys::key::{IKey, Key};
use crate::keys::KeyType;
use crate::platform::base::base_object::{BaseObject, SerializableObject};
use crate::platform::base::serializable_object::{SerializableKey, SerializableValue};
use crate::platform::document::Document;
use crate::platform::document::document::{DocumentKey, DocumentValue};
use crate::platform::identity::identity::Identity;
use crate::platform::transition::r#type::Type;
use crate::platform::transition::transition;
use crate::util::TimeUtil;

pub const TS_VERSION: u16 = 0x00000001;

pub trait ITransition {
    fn sign_with_key(&mut self, private_key: &dyn IKey, index: u32, identity: &Identity);
}

pub enum TransitionKey {
    ProtocolVersion,
    Signature,
    SignaturePublicKeyId,
    Type,
}

impl SerializableKey for TransitionKey {
    fn as_str(&self) -> &str {
        match self {
            TransitionKey::ProtocolVersion => "protocolVersion",
            TransitionKey::Type => "type",
            TransitionKey::Signature => "signature",
            TransitionKey::SignaturePublicKeyId => "signaturePublicKeyId",

        }
    }
}

pub enum TransitionValue {
    Bytes(&'static Vec<u8>),
    U32(u32),
    Uint256(&'static UInt256),
    ArrayOfDictionaries(&'static Vec<HashMap<dyn SerializableKey, dyn SerializableValue>>),
}

impl SerializableValue for TransitionValue {}

#[derive(Debug)]
pub struct Transition {
    pub base: BaseObject,

    pub version: u16,
    pub r#type: Type,
    pub identity_unique_id: UInt256,
    pub credit_fee: u64,
    pub transition_hash: UInt256,


    pub created_timestamp: u64,
    pub registered_timestamp: u64,

    documents: Vec<Document>,
    actions: Vec<u64>,
    // signature: Vec<u8>,
    pub signature_type: &'static KeyType,
    pub signature_data: Option<&'static Vec<u8>>,
    pub signature_public_key_id: u32,

    // @property (nonatomic, readonly, getter=toData) NSData *data;
    //
    // @property (nonatomic, readonly) uint32_t signature_public_key_id;

    saved: bool,
}

impl ITransition for Transition {
    fn sign_with_key(&mut self, private_key: &dyn IKey, index: u32, identity: &Identity) {
        if self.r#type == Type::IdentityRegistration {
            assert_eq!(index, u32::MAX, "index must not exist");
        } else {
            assert_ne!(index, u32::MAX, "index must exist");
        }
        // ATTENTION If this ever changes from ECDSA, change the max signature size defined above
        // DSLogPrivate(@"Private Key is %@", [privateKey serializedPrivateKeyForChain:self.chain]);
        // DSLogPrivate(@"Signing %@ with key %@", [self serializedBaseDataHash].hexString, privateKey.publicKeyData.hexString);
        self.signature_type = private_key.r#type();
        self.signature_data = Some(&private_key.sign(&self.serialized_base_data_hash()));
        self.signature_public_key_id = index;
        self.transition_hash = UInt256::sha256(&self.to_data());
    }


}

impl SerializableObject for Transition {
    fn chain(&self) -> &Chain {
        self.base.chain
    }

    fn key_value_dictionary(&mut self) -> &HashMap<dyn SerializableKey, dyn SerializableValue> {
        &self.base.key_value_dictionary.unwrap_or_else(|| {
            let mut json = self.base_key_value_dictionary();
            json.insert(TransitionKey::Signature, TransitionValue::Bytes(&self.signature));
            if self.signature_public_key_id != u32::MAX {
                json.insert(TransitionKey::SignaturePublicKeyId, TransitionValue::U32(self.signature_public_key_id));
            }
            self.base.key_value_dictionary = Some(json);
            json
        })
    }

    fn base_key_value_dictionary(&self) -> &HashMap<dyn SerializableKey, dyn SerializableValue> {
        let mut json = HashMap::<dyn SerializableKey, dyn SerializableValue>::new();
        json.insert(TransitionKey::ProtocolVersion, TransitionValue::U32(self.chain().params.platform_protocol_version));
        json.insert(TransitionKey::Type, self.r#type.clone());
        &json
    }

    fn serialized(&mut self) -> Vec<u8> {
        self.base.serialized()
    }

    fn serialized_base_data(&mut self) -> Vec<u8> {
        self.base.serialized_base_data()
    }

    fn serialized_hash(&mut self) -> Vec<u8> {
        self.base.serialized_hash()
    }

    fn serialized_base_data_hash(&mut self) -> Vec<u8> {
        self.base.serialized_base_data_hash()
    }
}

impl Transition {

    pub fn init_with_data(data: Vec<u8>, chain: &Chain) -> Option<Self> {
        if let Ok(data) = minicbor::decode::<HashMap<dyn SerializableKey, dyn SerializableValue>>(&data) {
            let mut s = Self {
                base: BaseObject { chain, key_value_dictionary: Some(&data), ..Default::default() },
                version: TS_VERSION,
                r#type: Type::Documents,
                identity_unique_id,
                credit_fee: 0,
                transition_hash: Default::default(),
                created_timestamp: SystemTime::seconds_since_1970(),
                registered_timestamp: 0,
                documents: vec![],
                actions: vec![],
                signature_type: &KeyType::ECDSA,
                signature_data: None,
                signature_public_key_id: 0,
                saved: false
            };
            s.apply_key_value_dictionary(data);
            Some(s)
        } else {
            None
        }
    }
    pub fn init_of_type_with_transition_version(r#type: Type, version: u16, identity_unique_id: UInt256, chain: &Chain) -> Self {
        Self {
            r#type,
            version,
            identity_unique_id,
            created_timestamp: SystemTime::seconds_since_1970(),
            base: BaseObject { chain, ..Default::default() },
            ..Default::default()
        }
    }

    pub fn init_with_transition_version(version: u16, identity_unique_id: UInt256, chain: &Chain) -> Self {
        // _version = TS_VERSION;
        // _chain = chain;
        // self.saved = FALSE;
        // self.createdTimestamp = [NSDate timeIntervalSince1970];
        Self::init_of_type_with_transition_version(Type::Documents, version, identity_unique_id, chain)
    }


    pub fn documents_as_array_of_dictionaries(&self) -> Vec<HashMap<DocumentKey, DocumentValue>> {
        self.documents.iter().map(|document| document.object_dictionary()).collect()
    }

    fn apply_key_value_dictionary(&mut self, dictionary: HashMap<dyn SerializableKey, dyn SerializableValue>) {
        self.base.key_value_dictionary = Some(&dictionary);
        if let Some(TransitionValue::Bytes(data)) = dictionary.get(&TransitionKey::Signature) {
            self.signature_data = Some(data);
        }
        if let Some(TransitionValue::U32(&id)) = dictionary.get(&TransitionKey::SignaturePublicKeyId) {
            self.signature_public_key_id = id;
        }
    }

    pub fn check_transition_signature(&mut self, key: &dyn IKey) -> bool {
        if let Some(signature) = &self.signature_data {
            key.verify(&self.serialized_base_data_hash(), signature)
        } else {
            false
        }
    }

    pub fn check_transition_signed_by_blockchain_identity(&mut self, identity: &Identity) -> bool {
        if let Some(signature) = &self.signature_data {
            identity.verify_signature(signature, &KeyType::ECDSA, &self.serialized_base_data_hash())
        } else {
            false
        }
    }




    /// size in bytes if signed, or estimated size assuming compact pubkey sigs
    pub fn size(&mut self) -> usize {
        // if let Some(hash) = self.transition_hash {}
        if self.transition_hash.is_zero() {
            // TODO: (inherited) figure this out (probably wrong)
            self.base.serialized().len()
        } else {
            self.data.len()
        }
    }

    pub fn to_data(&mut self) -> Vec<u8> {
        self.base.serialized()
    }

}
