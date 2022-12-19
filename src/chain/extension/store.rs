use std::collections::HashMap;
use crate::crypto::UInt256;
use crate::chain::block::IBlock;
use crate::chain::chain::{Chain, KEEP_RECENT_TERMINAL_BLOCKS};
use crate::chain::wallet::bip39_mnemonic::BIP39_CREATION_TIME;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::block::BlockEntity;
use crate::storage::models::chain::chain::{ChainAggregate, ChainEntity};
use crate::storage::models::tx::transaction::TransactionEntity;

pub trait Store {
    fn chain_entity_in_context(&self, context: &ManagedContext) -> ChainAggregate;
    fn save(&self);
    fn save_in_context(&self, context: &ManagedContext);
    fn save_block_locators(&mut self);
    fn save_terminal_blocks(&self);

    /// this is used to save transactions atomically with the block, needs to be called before switching threads to save the block
    fn prepare_for_incoming_transaction_persistence_for_block_save_with_number(&self, block_number: u32);
    /// this is used to save transactions atomically with the block
    fn persist_incoming_transactions_attributes_for_block_save_with_number(&self, block_number: u32, context: &ManagedContext);
}

impl Store for Chain {

    fn chain_entity_in_context(&self, context: &ManagedContext) -> ChainAggregate {
        ChainEntity::aggregate_for_type(self.params.chain_type, &self.checkpoints, context).unwrap()
    }

    fn save(&self) {
        if self.is_transient {
            return;
        }
        self.save_in_context(self.chain_context());
    }

    fn save_in_context(&self, context: &ManagedContext) {
        if self.is_transient {
            return;
        }
        match ChainEntity::update_block_hash_and_governance(
            self.params.chain_type,
            &self.masternode_base_block_hash,
            self.total_governance_object_count,
            context) {
            Ok(count) => println!("chain saved {}", count),
            Err(err) => println!("chain saved error: {:?}", err),
        }
    }

    fn save_block_locators(&mut self) {
        if self.is_transient {
            return;
        }
        self.prepare_for_incoming_transaction_persistence_for_block_save_with_number(self.last_sync_block_height());
        match self.last_sync_block() {
            Some(last_block) => {
                let sync_locators = &self.chain_sync_block_locator_array();
                self.last_persisted_chain_info.locators = Some(self.block_locator_array_on_or_before_timestamp(BIP39_CREATION_TIME, false));
                self.persist_incoming_transactions_attributes_for_block_save_with_number(last_block.height(), self.chain_context());
                match TransactionEntity::update_height_and_timestamps(&self.transaction_hash_heights, &self.transaction_hash_timestamps, self.chain_context()) {
                    Ok(saved) => println!("TransactionEntity::update_height_and_timestamps ok: {}", saved),
                    Err(err) => println!("TransactionEntity::update_height_and_timestamps error: {:?}", err)
                }
                match ChainEntity::save_block_locators(self.params.chain_type, last_block, sync_locators, self.chain_context()) {
                    Ok(saved) => println!("ChainEntity::save_block_locators ok: {}", saved),
                    Err(err) => println!("ChainEntity::save_block_locators error: {:?}", err)
                }
                self.transaction_hash_heights.clear();
                self.transaction_hash_timestamps.clear();
            },
            None => println!("save_block_locators: no last_sync_block")
        }
    }

    fn save_terminal_blocks(&mut self) {
        if self.is_transient {
            return;
        }
        let mut blocks = HashMap::<UInt256, dyn IBlock>::new();
        let mut b = self.last_terminal_block();
        let end_height = b.unwrap().height();
        let mut start_height = b.unwrap().height();
        let terminal_blocks = self.terminal_blocks.clone();
        while b.is_some() && start_height > self.last_checkpoint().unwrap().height && end_height - start_height < KEEP_RECENT_TERMINAL_BLOCKS {
            blocks.insert(b.unwrap().block_hash(), b.unwrap().clone());
            start_height = b.unwrap().height();
            b = terminal_blocks.get(&b.unwrap().prev_block());
        }
        if start_height == b.unwrap().height() {
            // only save last one then
            blocks.insert(b.unwrap().block_hash(), b.unwrap().clone());
        }

        if self.options.keep_headers {
            // only remove orphan chains
            match BlockEntity::delete_orphan_blocks(self.params.chain_type, start_height, blocks.keys().collect(), self.chain_context()) {
                Ok(deleted) => println!("{} recent orphans removed from disk", deleted),
                Err(err) => println!("failed to remove orphans")
            }
        } else {
            match BlockEntity::delete_blocks(self.params.chain_type, blocks.keys().collect(), self.chain_context()) {
                Ok(deleted) => println!("{} blocks removed from disk", deleted),
                Err(err) => println!("failed to remove blocks")
            }
        }

        match BlockEntity::update_blocks(self.params.chain_type, &mut blocks, self.chain_context()) {
            Ok(updated) => println!("{} blocks updated on disk", updated),
            Err(err) => println!("failed to update blocks")
        }
    }

    fn prepare_for_incoming_transaction_persistence_for_block_save_with_number(&self, block_number: u32) {
        self.wallets.iter().for_each(|mut wallet| {
            wallet.prepare_for_incoming_transaction_persistence_for_block_save_with_number(block_number);
        });
    }

    fn persist_incoming_transactions_attributes_for_block_save_with_number(&self, block_number: u32, context: &ManagedContext) {
        self.wallets.iter().for_each(|mut wallet| {
            wallet.persist_incoming_transactions_attributes_for_block_save_with_number(block_number, context);
        });
    }

}
