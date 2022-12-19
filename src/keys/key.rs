use crate::chain::chain::Chain;
use crate::crypto::UInt256;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::uint256_index_path::IndexPath;
use crate::keys::KeyType;
use crate::platform::base::serializable_object::SerializableValue;
use crate::util::crypto;

pub trait IKey: SerializableValue {
    fn r#type(&self) -> &KeyType {
        panic!("Should be overriden in implementation")
    }
    fn address_with_public_key_data(&self, chain: &Chain) -> Option<String> {
        crypto::address_with_public_key_data(self.public_key_data(), chain)
    }

    fn decrypt<K: IKey>(&self, data: &Vec<u8>, public_key: &K) -> Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn encrypt<K: IKey>(&self, data: &Vec<u8>, public_key: &K) -> Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn verify(&self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        panic!("Should be overriden in implementation")
    }
    fn private_derive_to_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        panic!("Should be overriden in implementation")
    }
    fn private_key_data(&self) -> Option<Vec<u8>> {
        panic!("Should be overriden in implementation")
    }
    fn public_key_data(&self) -> &Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn extended_public_key_data(&self) -> &Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn private_derive_to256bit_derivation_path(&self, derivation_path: &dyn IDerivationPath) -> Option<&Self> {
        panic!("Should be overriden in implementation")
    }

    fn serialized_private_key_for_chain(&self, chain: &Chain) -> Option<String> {
        panic!("Should be overriden in implementation")
    }


    fn hmac_256_data(&self, data: &Vec<u8>) -> UInt256 {
        panic!("Should be overriden in implementation")
    }
}

pub struct Key {}

impl SerializableValue for Key {
    fn as_data(&self) -> &[u8] {
        todo!()
    }
}

impl IKey for Key {}

// impl SerializableValue for dyn IKey {
//     fn as_data(&self) -> &[u8] {
//         self.
//     }
// }
