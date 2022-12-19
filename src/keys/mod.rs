use bls_signatures::bip32::ExtendedPrivateKey;
use crate::consensus::Encodable;
use crate::derivation::uint256_index_path::IndexPath;
use crate::keys::bls_key::BLSKey;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::platform::base::serializable_object::SerializableValue;

pub mod bls_key;
pub mod key;
pub mod ecdsa_key;

#[derive(Debug)]
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


impl SerializableValue for KeyType {
    fn as_data(&self) -> &[u8] {
        let mut writer = Vec::<u8>::new();
        match self {
            KeyType::ECDSA => 0u8.enc(&mut writer),
            KeyType::BLS => 1u8.enc(&mut writer),
            KeyType::BLSBasic => 2u8.enc(&mut writer)
        }
        writer.as_slice()
    }
}

impl KeyType {

    pub(crate) fn public_key_from_extended_public_key_data<T>(&self, data: &Vec<u8>, index_path: &IndexPath<T>) -> Option<Vec<u8>> {
        match self {
            KeyType::ECDSA => ECDSAKey::public_key_from_extended_public_key_data(data, index_path),
            KeyType::BLS => BLSKey::public_key_from_extended_public_key_data(data, index_path, true),
            KeyType::BLSBasic => BLSKey::public_key_from_extended_public_key_data(data, index_path, false),
        }
    }

    pub(crate) fn private_key_from_extended_private_key_data<T>(&self, data: &Vec<u8>, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        match self {
            KeyType::ECDSA => ECDSAKey::init_with_extended_private_key_data(data),
            KeyType::BLS => BLSKey::init_with_bls_extended_private_key(data, index_path, true),
            KeyType::BLSBasic => BLSKey::init_with_bls_extended_private_key(data, index_path, false)
        }
    }

    pub(crate) fn key_with_private_key_data<T>(&self, data: &Vec<u8>, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_secret(data, true),
            KeyType::BLS => BLSKey::key_with_private_key(data, true),
            KeyType::BLSBasic => BLSKey::key_with_private_key(data, false),
        }
    }

    pub(crate) fn key_with_seed_data<T>(&self, data: &Vec<u8>) -> Option<dyn IKey> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_seed_data(data),
            KeyType::BLS => BLSKey::extended_private_key_with_seed_data(data, true),
            KeyType::BLSBasic => BLSKey::extended_private_key_with_seed_data(data, false),
        }
    }

    pub(crate) fn key_with_public_key_data<T>(&self, data: &Vec<u8>) -> Option<dyn IKey> {
        match self {
            KeyType::ECDSA => Some(ECDSAKey::key_with_public_key_data(data)),
            KeyType::BLS => BLSKey::key_with_public_key_data(data, true),
            KeyType::BLSBasic => BLSKey::key_with_public_key_data(data, false),
        }
    }

    pub(crate) fn key_with_extended_public_key_data<T>(&self, data: &Vec<u8>) -> Option<dyn IKey> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_extended_public_key_data(data),
            KeyType::BLS => BLSKey::key_with_extended_public_key_data(data, true),
            KeyType::BLSBasic => BLSKey::key_with_extended_public_key_data(data, false),
        }
    }

    pub(crate) fn key_with_extended_private_key_data<T>(&self, data: &Vec<u8>) -> Option<dyn IKey> {
        match self {
            KeyType::ECDSA => ECDSAKey::key_with_extended_private_key_data(data),
            KeyType::BLS => BLSKey::key_with_extended_private_key_data(data, true),
            KeyType::BLSBasic => BLSKey::key_with_extended_private_key_data(data, false),
        }
    }

}
