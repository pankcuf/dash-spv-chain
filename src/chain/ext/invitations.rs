use crate::chain::chain::Chain;
use crate::chain::wallet::extension::invitations::WalletInvitations;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::invitation::InvitationEntity;
use crate::storage::models::entity::Entity;

pub trait Invitations {
    fn local_blockchain_invitations_count(&self) -> u32;
    fn wipe_blockchain_invitations_persisted_data_in_context(&mut self, context: &ManagedContext);
}

impl Invitations for Chain {
    fn local_blockchain_invitations_count(&self) -> u32 {
        self.wallets.iter().map(|wallet| wallet.invitations_count()).sum()
    }

    fn wipe_blockchain_invitations_persisted_data_in_context(&mut self, context: &ManagedContext) {
        context.perform_block_and_wait(|context| {
            InvitationEntity::delete_for_chain_type::<crate::schema::invitations::dsl::invitations>(self.r#type(), context)
                .expect("Can't delete invitation entities");
        })
    }

}
