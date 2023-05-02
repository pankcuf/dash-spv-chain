use std::fmt::Debug;
use crate::chain::params::ScriptMap;
use crate::crypto::UInt256;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::index_path::IndexPath;
use crate::keys::KeyType;
use crate::util::address::Address;

pub trait IKey: Send + Sync + Debug /*where Self: Sized*/ {
    fn r#type(&self) -> KeyType {
        panic!("Should be overriden in implementation")
    }
    fn address_with_public_key_data(&mut self, script: &ScriptMap) -> Option<String> {
        Some(Address::with_public_key_data(&self.public_key_data(), script))
    }

    fn decrypt(&self, data: &Vec<u8>, public_key: &Self) -> Vec<u8> where Self: Sized {
        panic!("Should be overriden in implementation")
    }
    fn encrypt(&self, data: &Vec<u8>, public_key: &Self) -> Vec<u8> where Self: Sized {
        panic!("Should be overriden in implementation")
    }
    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn verify(&self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        panic!("Should be overriden in implementation")
    }
    fn private_derive_to_path(&self, index_path: &IndexPath<u32>) -> Option<&dyn IKey> {
        panic!("Should be overriden in implementation")
    }
    // fn private_derive_to_path(&self, index_path: &IndexPath<u32>) -> Option<Self> where Self: Sized {
    //     panic!("Should be overriden in implementation")
    // }
    fn private_key_data(&self) -> Option<Vec<u8>> {
        panic!("Should be overriden in implementation")
    }
    fn public_key_data(&mut self) -> Vec<u8> {
        panic!("Should be overriden in implementation")
    }
    fn extended_private_key_data(&self) -> Option<Vec<u8>> {
        panic!("Should be overriden in implementation")
    }
    fn extended_public_key_data(&mut self) -> Option<Vec<u8>> {
        panic!("Should be overriden in implementation")
    }
    // fn public_derive_to_256bit_derivation_path(&mut self, derivation_path: &dyn IDerivationPath) -> Option<Self> where Self: Sized {
    //     self.public_derive_to_256bit_derivation_path_with_offset(derivation_path, 0)
    // }
    // fn public_derive_to_256bit_derivation_path_with_offset(&mut self, derivation_path: &dyn IDerivationPath, offset: usize) -> Option<Self> where Self: Sized {
    //     panic!("Should be overriden in implementation")
    // }
    // fn private_derive_to_256bit_derivation_path(&self, derivation_path: &dyn IDerivationPath) -> Option<Self> where Self: Sized {
    //     self.private_derive_to_path(&derivation_path.base_index_path())
    // }

    fn public_derive_to_256bit_derivation_path(&mut self, derivation_path: &dyn IDerivationPath) -> Option<&dyn IKey> {
        self.public_derive_to_256bit_derivation_path_with_offset(derivation_path, 0)
    }
    fn public_derive_to_256bit_derivation_path_with_offset(&mut self, derivation_path: &dyn IDerivationPath, offset: usize) -> Option<&dyn IKey> {
        panic!("Should be overriden in implementation")
    }

    fn private_derive_to_256bit_derivation_path(&self, derivation_path: &dyn IDerivationPath) -> Option<&dyn IKey> {
        self.private_derive_to_path(&derivation_path.base_index_path())
    }

    fn serialized_private_key_for_chain(&self, script: &ScriptMap) -> String {
        panic!("Should be overriden in implementation")
    }


    fn hmac_256_data(&self, data: &Vec<u8>) -> UInt256 {
        panic!("Should be overriden in implementation")
    }

    fn forget_private_key(&mut self) {
        panic!("Should be overriden in implementation")
    }
}
