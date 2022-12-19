use std::collections::HashMap;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::platform::identity::identity::Identity;

pub struct IdentitiesManager {
    pub chain: &'static Chain,
    pub foreign_blockchain_identities: HashMap<UInt256, Identity>,

}

impl IdentitiesManager {
    pub(crate) fn register_foreign_identity(&self, identity: &mut Identity) {
        todo!()
    }
}

impl IdentitiesManager {
    pub fn clear_external_blockchain_identities(&mut self) {
        self.foreign_blockchain_identities.clear();
    }

    pub fn foreign_blockchain_identity_with_unique_id(&mut self, unique_id: UInt256) -> Option<&Identity> {
        self.foreign_blockchain_identity_with_unique_id_create_if_missing(unique_id, false/*, None*/)
    }

    pub fn foreign_blockchain_identity_with_unique_id_create_if_missing(&mut self, unique_id: UInt256, create_if_missing: bool/*, context: NSManagedObjectContext*/) -> Option<&Identity> {
        //foreign blockchain identities are for local blockchain identies' contacts, not for search.
        if let Some(foreign_blockchain_identity) = self.foreign_blockchain_identities.get(&unique_id) {
            //NSAssert(context ? [foreignBlockchainIdentity blockchainIdentityEntityInContext:context] : foreignBlockchainIdentity.blockchainIdentityEntity, @"Blockchain identity entity should exist");
            Some(foreign_blockchain_identity)
        } else if create_if_missing {
            let foreign_blockchain_identity = Identity::init_with(unique_id, false, self.chain);
            // TODO: store in local DB
            //foreign_blockchain_identity.save_initial_in_context(context);
            self.foreign_blockchain_identities.insert(unique_id, foreign_blockchain_identity);
            Some(&foreign_blockchain_identity)
        } else {
            None
        }
    }

}
