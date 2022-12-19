use std::collections::HashMap;
use crate::crypto::UInt256;
use crate::keys::key::IKey;
use crate::storage::models::account::user::UserEntity;

pub struct PotentialContact {
    pub username: String,
    pub display_name: String,
    pub avatar_path: String,
    pub public_message: String,
    pub associated_identity_unique_id: UInt256,

    key_dictionary: HashMap<u32, dyn IKey>,

}

impl PotentialContact {
    pub fn init_with_username(username: String) -> Self {
        Self {
            username,
            associated_identity_unique_id: UInt256::MIN,
            key_dictionary: HashMap::new(),
            ..Default::default()
        }
    }

    pub fn init_with_usename_and_avatar(username: String, avatar_path: String, public_message: String) -> Self {
        Self {
            username,
            avatar_path,
            public_message,
            associated_identity_unique_id: UInt256::MIN,
            key_dictionary: HashMap::new(),
            ..Default::default()
        }
    }

    pub fn init_with_dashpay_user(entity: UserEntity) -> Self {
        // todo: impl
        // let username_entity = entity.identity_id
        // DSBlockchainIdentityUsernameEntity *usernameEntity = [dashpayUserEntity.associatedBlockchainIdentity.usernames anyObject];
        // self = [self initWithUsername:usernameEntity.stringValue avatarPath:dashpayUserEntity.avatarPath publicMessage:dashpayUserEntity.publicMessage];
        // if (self) {
        //     _associatedBlockchainIdentityUniqueId = dashpayUserEntity.associatedBlockchainIdentity.uniqueID.UInt256;
        // }
        // Self {
        //     username,
        //     avatar_path,
        //     public_message,
        //     associated_identity_unique_id: UInt256::MIN,
        //     key_dictionary: HashMap::new(),
        //     ..Default::default()
        // }

    }

    pub fn add_public_key(&mut self, key: &dyn IKey, index: u32) {
        self.key_dictionary.insert(index, key);
    }

    pub fn public_key_at_index(&self, index: u32) -> Option<&dyn IKey> {
        self.key_dictionary.get(&index)
    }

}
