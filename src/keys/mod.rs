use crate::crypto::byte_util::BytesDecodable;
use crate::crypto::UInt384;
use crate::derivation::index_path::IndexPath;
use crate::keys::bls_key::BLSKey;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;

pub mod bls_key;
pub mod key;
pub mod ecdsa_key;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    ECDSA = 0,
    BLS = 1,
    BLSBasic = 2,
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::ECDSA
    }
}

impl From<i16> for KeyType {
    fn from(orig: i16) -> Self {
        match orig {
            0 => KeyType::ECDSA,
            1 => KeyType::BLS,
            2 => KeyType::BLSBasic,
            _ => KeyType::default(),
        }
    }
}

impl From<KeyType> for i16 {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::ECDSA => 0,
            KeyType::BLS => 1,
            KeyType::BLSBasic => 2
        }
    }
}

impl From<&KeyType> for u8 {
    fn from(value: &KeyType) -> Self {
        match value {
            KeyType::ECDSA => 0,
            KeyType::BLS => 1,
            KeyType::BLSBasic => 2
        }
    }
}

impl KeyType {

    pub fn derivation_string(&self) -> String {
        match self {
            KeyType::ECDSA => "_BLS_",
            _ => ""
        }.to_string()
    }

    pub(crate) fn public_key_from_extended_public_key_data(&self, data: &Vec<u8>, index_path: &IndexPath<u32>) -> Option<Vec<u8>> {
        match self {
            KeyType::ECDSA => ECDSAKey::public_key_from_extended_public_key_data(data, index_path),
            KeyType::BLS => BLSKey::public_key_from_extended_public_key_data(data, index_path, true),
            KeyType::BLSBasic => BLSKey::public_key_from_extended_public_key_data(data, index_path, false),
        }
    }

    pub(crate) fn private_key_from_extended_private_key_data<KEY>(&self, data: &Vec<u8>) -> Option<KEY> where KEY: IKey + Sized {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_private_key_data(data),
            KeyType::BLS => BLSKey::init_with_extended_private_key_data(data, true),
            KeyType::BLSBasic => BLSKey::init_with_extended_private_key_data(data, false),
        }
    }

    pub(crate) fn key_with_private_key_data(&self, data: &Vec<u8>) -> Option<&dyn IKey> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_secret(data, true).map(|key| &key),
            KeyType::BLS => BLSKey::key_with_private_key(data, true),
            KeyType::BLSBasic => BLSKey::key_with_private_key(data, false),
        }
    }

    pub(crate) fn key_with_seed_data(&self, data: &Vec<u8>) -> Option<Box<dyn IKey>> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_seed_data(data).map(Box::new),
            KeyType::BLS => BLSKey::extended_private_key_with_seed_data(data, true).map(Box::new),
            KeyType::BLSBasic => BLSKey::extended_private_key_with_seed_data(data, false).map(Box::new),
        }
    }

    pub(crate) fn key_with_public_key_data(&self, data: &Vec<u8>) -> Option<Box<dyn IKey>> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_public_key_data(data).map(Box::new),
            KeyType::BLS => Some(Box::new(BLSKey::key_with_public_key(UInt384::from_bytes(data, &mut 0).unwrap(), true))),
            KeyType::BLSBasic => Some(Box::new(BLSKey::key_with_public_key(UInt384::from_bytes(data, &mut 0).unwrap(), false))),
        }
    }

    pub(crate) fn key_with_extended_public_key_data(&self, data: &Vec<u8>) -> Option<&dyn IKey> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_public_key_data(data),
            KeyType::BLS => BLSKey::init_with_extended_public_key_data(data, true),
            KeyType::BLSBasic => BLSKey::init_with_extended_public_key_data(data, false),
        }.map(|k| &k)
    }

    // pub(crate) fn key_with_extended_private_key_data<T>(&self, data: &Vec<u8>) -> Option<&dyn IKey> {
    //     match self {
    //         KeyType::ECDSA => ECDSAKey::init_with_extended_private_key_data(data),
    //         KeyType::BLS => BLSKey::init_with_extended_private_key_data(data, true),
    //         KeyType::BLSBasic => BLSKey::init_with_extended_private_key_data(data, false),
    //     }.map(|k| &k)
    // }


    pub fn private_key_at_index_path_from_seed<KEY: IKey>(&self, index_path: &IndexPath<u32>, seed: &Vec<u8>) -> Option<KEY> {
        self.key_with_seed_data(seed)
            .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(self)
                .and_then(|key| key.private_derive_to_path(index_path)))

    }
    pub fn private_keys_at_index_paths<KEY: IKey>(&self, index_paths: Vec<IndexPath<u32>>, seed: &Vec<u8>) -> Vec<KEY> {
        if index_paths.is_empty() {
            vec![]
        } else {
            self.key_with_seed_data(seed)
                .and_then(|top_key| top_key.private_derive_to_256bit_derivation_path(self)
                    .map(|key| index_paths.iter().filter_map(|index_path| key.private_derive_to_path(index_path)).collect::<Vec<_>>()))
                .unwrap_or(vec![])
        }

    }

}
