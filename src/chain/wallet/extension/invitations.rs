use std::collections::HashMap;
use hashes::{Hash, sha256d};
use crate::chain::tx::credit_funding_transaction::CreditFundingTransaction;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::byte_util::{AsBytes, Reversable, Zeroable};
use crate::crypto::primitives::utxo::UTXO;
use crate::crypto::UInt256;
use crate::keychain;
use crate::keychain::keychain::Keychain;
use crate::platform::identity::invitation::Invitation;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::invitation::InvitationEntity;
use crate::storage::models::entity::EntityConvertible;
use crate::storage::models::tx::special::credit_funding_transaction::CreditFundingTransactionEntity;
use crate::storage::models::tx::transaction::TransactionEntity;

/// Wallet operations with invitations
pub trait WalletInvitations {
    fn blockchain_invitations_count(&self) -> u32;
    fn blockchain_invitations(&mut self) -> Option<&HashMap<UTXO, Invitation>>;
    fn blockchain_invitation_for_unique_id<T>(&self, unique_id: UInt256) -> Option<&Invitation>;
    fn unused_blockchain_invitation_index(&self) -> u32;
    fn create_blockchain_invitation(&self) -> Invitation;
    fn create_blockchain_invitation_using_derivation_index(&self, index: u32) -> Invitation;
    fn unregister_blockchain_invitation(&mut self, invitation: &Invitation);
    fn add_blockchain_invitation(&mut self, invitation: Invitation);
    fn register_blockchain_invitation(&self, mut invitation: Invitation);
    fn contains_blockchain_invitation(&self, invitation: &Invitation) -> bool;
    fn wipe_blockchain_invitations_in_context(&self, context: &ManagedContext);

}

impl WalletInvitations for Wallet {
    fn blockchain_invitations_count(&self) -> u32 {
        self.invitations.len() as u32
    }

    // This loads all the identities that the wallet knows about.
    // If the app was deleted and reinstalled the identity information will remain from the
    // keychain but must be reaquired from the network.
    fn blockchain_invitations(&mut self) -> Option<&HashMap<UTXO, Invitation>> {
        if self.invitations_loaded {
            return Some(&self.invitations);
        }
        if let Ok(key_chain_dictionary) = Keychain::get_dict::<UTXO, u32>(self.wallet_blockchain_invitations_key(), vec![/*@[[NSNumber class], [NSData class]]*/]) {
            let mut invitations = HashMap::<UTXO, Invitation>::new();
            key_chain_dictionary.iter().for_each(|(&locked_outpoint, &index)| {
                // TODO: get the identity from core data
                let context = self.chain.chain_context();
                let invitation_entities_count = InvitationEntity::count_invitations_for_chain_type(self.chain.params.chain_type, context).unwrap_or(0);
                if invitation_entities_count != key_chain_dictionary.len() {
                    println!("Unmatching blockchain invitations count");
                }
                let mut invitation: Option<Invitation> = None;
                let identity_unique_id = UInt256::sha256d(locked_outpoint.as_bytes());
                if let Ok(invitation_entity) = InvitationEntity::get_by_identity_unique_id(&identity_unique_id, context) {
                    invitation = Some(Invitation::init_at_index_with_locked_outpoint_and_invitation_entity(
                        index, &locked_outpoint, self, &invitation_entity));
                } else {
                    // No blockchain identity is known in core data
                    match CreditFundingTransactionEntity::get_by_tx_hash(&locked_outpoint.hash.clone().reversed(), context) {
                        Ok((credit_regitration_transaction_entity, base_entity)) => {
                            // The registration funding transaction exists
                            // Weird but we should recover in this situation
                            let registration_transaction = CreditFundingTransaction::from_entity((credit_regitration_transaction_entity, base_entity), context);
                            let registration_funding_derivation_path = self.chain.derivation_path_factory.blockchain_identity_invitation_funding_derivation_path_for_wallet(self);
                            let correct_index = registration_transaction.check_derivation_path_index_for_wallet(&registration_funding_derivation_path, index);
                            if !correct_index {
                                assert!(false, "We should implement this");
                                None
                            } else {
                                let mut invitation = Invitation::init_at_with_funding_transaction(index, &registration_transaction, self);
                                invitation.register_in_wallet();
                                Some(invitation)
                            }
                        },
                        Err(..) => {
                            // We also don't have the registration funding transaction
                            let mut invitation = Invitation::init_at_index_with_locked_outpoint(index, &locked_outpoint, self);
                            invitation.register_in_wallet_for_blockchain_identity_unique_id(&identity_unique_id);
                            Some(invitation)
                        }
                    }
                }
                if let Some(invitation) = invitation {
                    invitations.insert(locked_outpoint, invitation)
                }
            });
            self.invitations = invitations;
            Some(&invitations)
        } else {
            None
        }
    }

    fn blockchain_invitation_for_unique_id<T>(&self, unique_id: UInt256) -> Option<&Invitation> {
        assert!(!unique_id.is_zero(), "uniqueId must not be null");
        self.invitations.values().find(|invitation| invitation.identity.unique_id == unique_id)
    }

    fn unused_blockchain_invitation_index(&self) -> u32 {
        self.invitations.values().map(|invitation| invitation.identity.index).max().unwrap_or(-1) + 1
    }

    fn create_blockchain_invitation(&self) -> Invitation {
        Invitation::init_at_index(self.unused_blockchain_invitation_index(), self)
    }

    fn create_blockchain_invitation_using_derivation_index(&self, index: u32) -> Invitation {
        Invitation::init_at_index(index, self)
    }

    fn unregister_blockchain_invitation(&mut self, invitation: &Invitation) {
        assert_eq!(invitation.wallet == self, "the blockchainInvitation you are trying to remove is not in this wallet");
        assert_ne!(invitation.identity.locked_outpoint, None, "the blockchainInvitation you are trying to remove has no identity");
        self.invitations.remove(&invitation.identity.locked_outpoint.unwrap());
        let mut key_chain_dictionary = Keychain::get_dict::<UTXO, u32>(self.wallet_blockchain_invitations_key(), vec![/*@[[NSNumber class], [NSData class]]*/]).unwrap_or(HashMap::new());
        key_chain_dictionary.remove(&invitation.identity.locked_outpoint.unwrap());
        Keychain::set_dict(key_chain_dictionary, self.wallet_blockchain_invitations_key(), false)
            .expect("Can't update invitations in keychain");
    }

    fn add_blockchain_invitation(&mut self, invitation: Invitation) {
        self.invitations.insert(invitation.identity.locked_outpoint.unwrap().clone(), invitation);
    }

    fn register_blockchain_invitation(&mut self, mut invitation: Invitation) {
        assert_ne!(invitation.identity.locked_outpoint, None, "the blockchainInvitation you are trying to remove has no identity");
        assert!(!invitation.identity.unique_id.is_zero(), "registrationTransactionHashData must not be null");
        if !self.invitations.contains(&invitation.identity.locked_outpoint.unwrap()) {
            self.add_blockchain_invitation(invitation);
        }
        let mut key_chain_dictionary = Keychain::get_dict::<UTXO, u32>(self.wallet_blockchain_invitations_key(), vec![/*@[[NSNumber class], [NSData class]]*/]).unwrap_or(HashMap::new());
        key_chain_dictionary.insert(invitation.identity.locked_outpoint.unwrap().clone(), invitation.identity.index.clone());
        Keychain::set_dict(key_chain_dictionary, self.wallet_blockchain_invitations_key(), false)
            .expect("Can't update invitations in keychain");
    }

    fn contains_blockchain_invitation(&self, invitation: &Invitation) -> bool {
        if let Some(outpoint) = invitation.identity.locked_outpoint {
            self.invitation.contains_key(outpoint)
        } else {
            false
        }
    }

    fn wipe_blockchain_invitations_in_context(&mut self, context: &ManagedContext) {
        self.invitations.values().for_each(|invitation| {
            self.unregister_blockchain_invitation(invitation);
            invitation.delete_persistent_object_and_save(false, context);
        });
    }

}
