use std::collections::HashMap;
use crate::crypto::byte_util::Zeroable;
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::chain::wallet::extension::identities::WalletIdentities;
use crate::platform::contract::contract::Contract;
use crate::platform::identity::identity::Identity;
use crate::chain::wallet::wallet::Wallet;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::entity::Entity;

pub trait Identities {
    fn local_blockchain_identities_count(&self) -> u32;
    fn local_blockchain_identities(&self) -> Vec<Identity>;
    fn local_blockchain_identities_by_unique_id_dictionary(&self) -> HashMap<UInt256, Identity>;
    fn blockchain_identity_for_unique_id(&self, unique_id: UInt256) -> Option<&Identity>;
    fn blockchain_identity_for_unique_id_in_wallet(&self, unique_id: UInt256) -> Option<(&Identity, &Wallet)>;
    fn blockchain_identity_that_created_contract(&self, contract: Contract, contract_id: UInt256) -> Option<(&Identity, &Wallet)>;
    fn blockchain_identity_for_unique_id_in_wallet_including_foreign_identites(&self, unique_id: UInt256, include_foreign_blockchain_identities: bool) -> Option<(&Identity, &Wallet)>;

    fn wipe_blockchain_identities_persisted_data(&mut self, context: &ManagedContext);
}

impl Identities for Chain {
    fn local_blockchain_identities_count(&self) -> u32 {
        self.wallets.iter().map(|wallet| wallet.blockchain_identities_count()).sum()
    }

    fn local_blockchain_identities(&self) -> Vec<Identity> {
        self.wallets
            .iter()
            .fold(Vec::new(), |mut identities, wallet| {
                identities.extend(wallet.identities.values());
                identities
            })
    }

    fn local_blockchain_identities_by_unique_id_dictionary(&self) -> HashMap<UInt256, Identity> {
        self.wallets.iter().fold(HashMap::new(), |mut identities, mut wallet| {
            wallet.blockchain_identities().values().for_each(|&identity| {
                identities.insert(identity.unique_id, identity);
            });
            identities
        })
    }

    fn blockchain_identity_for_unique_id(&self, unique_id: UInt256) -> Option<&Identity> {
        assert!(!unique_id.is_zero(), "unique_id must not be null");
        if let Some((identity, _wallet)) = self.blockchain_identity_for_unique_id_in_wallet_including_foreign_identites(unique_id, false) {
            Some(identity)
        } else {
            None
        }
    }

    fn blockchain_identity_for_unique_id_in_wallet(&self, unique_id: UInt256) -> Option<(&Identity, &Wallet)> {
        assert!(!unique_id.is_zero(), "unique_id must not be null");
        self.blockchain_identity_for_unique_id_in_wallet_including_foreign_identites(unique_id, false)
    }

    fn blockchain_identity_that_created_contract(&self, contract: Contract, contract_id: UInt256) -> Option<(&Identity, &Wallet)> {
        assert!(!contract_id.is_zero(), "contract_id must not be null");
        self.wallets.iter().find_map(|&wallet| {
            if let Some(identity) = wallet.blockchain_identity_that_created_contract(contract, contract_id) {
                Some((identity, wallet))
            } else {
                None
            }
        })
    }

    fn blockchain_identity_for_unique_id_in_wallet_including_foreign_identites(&self, unique_id: UInt256, include_foreign_blockchain_identities: bool) -> Option<(&Identity, &Wallet)> {
        assert!(!unique_id.is_zero(), "unique_id must not be null");
        self.wallets.iter().find_map(|&wallet| if let Some(identity) = wallet.blockchain_identity_for_unique_id(unique_id) {
            Some((identity, wallet))
        } else {
            None
        }).or_else({
            if include_foreign_blockchain_identities {
                self.identities_manager().foreign_blockchain_identity_with_unique_id(unique_id)
            } else {
                None
            }
        })
    }

    fn wipe_blockchain_identities_persisted_data(&mut self, context: &ManagedContext) {
        context.perform_block_and_wait(|context| {
            IdentityEntity::delete_for_chain_type(self.r#type(), self.chain_context())
                .expect("Can't delete identity entities");
        })
    }

}
