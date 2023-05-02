use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::platform::identity::key_status::KeyStatus;

// #[derive(Clone, Debug, Eq, Hash, PartialEq)]
// pub enum KeyDictionary {
//     Key = 0,
//     KeyType = 1,
//     KeyStatus = 2
// }
//
// #[derive(Clone, Debug)]
// pub enum KeyDictionaryValue {
//     Key(Box<dyn IKey>),
//     KeyType(KeyType),
//     KeyStatus(KeyStatus),
// }

#[derive(Debug)]
pub struct KeyInfo {
    pub key: Box<dyn IKey>,
    pub r#type: KeyType,
    pub status: KeyStatus,
}


// impl From<u32> for KeyDictionary {
//     fn from(value: u32) -> Self {
//         match value {
//             0 => KeyDictionary::Key,
//             1 => KeyDictionary::KeyType,
//             2 => KeyDictionary::KeyStatus,
//             _ => panic!("KeyDictionary: wrong key")
//         }
//     }
// }
//
// impl From<KeyDictionary> for u32 {
//     fn from(value: KeyDictionary) -> Self {
//         match value {
//             KeyDictionary::Key => 0,
//             KeyDictionary::KeyType => 1,
//             KeyDictionary::KeyStatus => 2,
//         }
//     }
// }
//
// impl From<KeyDictionary> for String {
//     fn from(value: KeyDictionary) -> Self {
//         match value {
//             KeyDictionary::Key => "0",
//             KeyDictionary::KeyType => "1",
//             KeyDictionary::KeyStatus => "2",
//         }.to_string()
//     }
// }
