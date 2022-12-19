use diesel::{Insertable, QuerySource, Table};
use diesel::insertable::CanInsertInSingleQuery;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use hashes::{Hash, sha256d};
use crate::blockdata::opcodes::all::OP_RETURN;
use crate::chain::chain::Chain;
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::chain::tx::Transaction;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::tx::transaction_input::TransactionInput;
use crate::chain::tx::transaction_output::TransactionOutput;
use crate::chain::tx::transaction_type::TransactionType;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::{UInt160, UInt256};
use crate::crypto::byte_util::{AsBytes, Reversable, Zeroable};
use crate::crypto::primitives::utxo::UTXO;
use crate::derivation::credit_funding_derivation_path::CreditFundingDerivationPath;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::simple_indexed_derivation_path::ISimpleIndexedDerivationPath;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};
use crate::storage::models::tx::special::credit_funding_transaction::CreditFundingTransactionEntity;
use crate::storage::models::tx::transaction::{NewTransactionEntity, TransactionEntity};
use crate::util::crypto::address_from_hash160_for_chain;

pub struct CreditFundingTransaction {
    pub base: Transaction,
    pub funding_amount: u64,
}

impl CreditFundingTransaction {

    pub fn locked_outpoint(&self) -> UTXO {
        self.outputs().iter().enumerate().find_map(|(i, output)| {
            if let Some(script) = &output.script {
                if script.len() == 22 && script[0] == OP_RETURN.into_u8() {
                    return Some(UTXO { hash: self.tx_hash().clone().reversed(), n: i as u32});
                }
            }
            None
        }).unwrap_or(UTXO::default())
    }

    pub fn credit_burn_identity_identifier(&self) -> UInt256 {
        let outpoint = self.locked_outpoint();
        if outpoint.is_zero() {
            UInt256::MIN
        } else {
            UInt256::sha256d(outpoint.as_bytes())
        }
    }

    pub fn credit_burn_public_key_hash(&self) -> UInt160 {
        self.outputs().iter().find_map(|output| {
            if let Some(script) = &output.script {
                if script.len() == 22 && script[0] == OP_RETURN.into_u8() {
                    return Some(UInt160(script[2..22] as [u8; 20]))
                }
            }
            None
        }).unwrap_or(UInt160::MIN)
    }

    fn credit_burn_address(&self) -> Option<String> {
        address_from_hash160_for_chain(&self.credit_burn_public_key_hash(), self.chain())
    }

    pub fn used_derivation_path_index_for_wallet(&self, wallet: &Wallet) -> u32 {
        let address = self.credit_burn_address();
        let path = self.chain().derivation_path_factory.blockchain_identity_registration_funding_derivation_path_for_wallet(wallet);
        path.index_of_known_address(address).unwrap_or(u32::MAX)
    }

    pub fn check_derivation_path_index_for_wallet_is(&self, wallet: &Wallet, index: u32) -> bool {
        let address = self.credit_burn_address();
        let path = self.chain().derivation_path_factory.blockchain_identity_registration_funding_derivation_path_for_wallet(wallet);
        // todo: check None == None comparison
        path.address_at_index(index) == address
    }

    pub fn check_invitation_derivation_path_index_for_wallet_is(&self, wallet: &Wallet, index: u32) -> bool {
        let address = self.credit_burn_address();
        let path = self.chain().derivation_path_factory.blockchain_identity_invitation_funding_derivation_path_for_wallet(wallet);
        // todo: check None == None comparison
        path.address_at_index(index) == address
    }

    pub fn mark_address_as_used_in_wallet(&self, wallet: &Wallet) {
        if let Some(address) = self.credit_burn_address() {
            let mut path = self.chain().derivation_path_factory.blockchain_identity_registration_funding_derivation_path_for_wallet(wallet);
            path.register_transaction_address(&address);
            path.register_addresses_with_gap_limit(10).expect("TODO: panic message");
        }
    }

    pub fn mark_invitation_address_as_used_in_wallet(&mut self, wallet: &Wallet) {
        if let Some(address) = self.credit_burn_address() {
            let mut path = self.chain().derivation_path_factory.blockchain_identity_invitation_funding_derivation_path_for_wallet(wallet);
            path.register_transaction_address(&address);
            path.register_addresses_with_gap_limit(10).expect("TODO: panic message");
        }
    }

    pub fn used_derivation_path_index(&self) -> u32 {
        let accounts = self.accounts();
        match accounts.len() {
            0 => u32::MAX,
            1 => self.used_derivation_path_index_for_wallet(&self.first_account().unwrap().wallet.unwrap()),
            _ => {
                accounts.iter().filter_map(|account| {
                        if let Some(wallet) = account.wallet {
                            if !wallets.contains(&wallet) {
                                return Some(wallet)
                            }
                        }
                    None
                }).map(|wallet| self.used_derivation_path_index_for_wallet(wallet))
                    .find(|der| der != u32::MAX)
                    .unwrap_or(u32::MAX)
            }
        }
    }
}

impl EntityConvertible for CreditFundingTransaction {
    fn to_entity<T, U>(&self) -> U
        where
            T: Table + QuerySource,
            T::FromClause: QueryFragment<Sqlite>,
            U: Insertable<T>, diesel::insertable::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite> {
        todo!()
    }

    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>> where T: Table, V: AsChangeset<Target=T> {
        todo!()
    }

    fn from_entity<T: Entity>(entity: (CreditFundingTransactionEntity, TransactionEntity), context: &ManagedContext) -> Self {
        todo!()
        // let base = match ChainEntity::get_by_id(entity.chain_id, context) {
        //     Ok(chain) =>
        // }
        // DSCreditFundingTransaction *transaction = (DSCreditFundingTransaction *)[super transactionForChain:chain];
        // transaction.type = DSTransactionType_Classic;
        // [self.managedObjectContext performBlockAndWait:^{
        //     transaction.instantSendLockAwaitingProcessing = [self.instantSendLock instantSendTransactionLockForChain:chain];
        // }];
        //
        // return transaction;

    }
}

impl ITransaction for CreditFundingTransaction {
    fn chain(&self) -> &Chain {
        self.base.chain()
    }

    fn r#type(&self) -> TransactionType {
        TransactionType::CreditFunding
    }

    fn block_height(&self) -> u32 {
        self.base.block_height()
    }

    fn tx_hash(&self) -> UInt256 {
        self.base.tx_hash()
    }

    fn inputs(&self) -> Vec<TransactionInput> {
        self.base.inputs()
    }

    fn outputs(&self) -> Vec<TransactionOutput> {
        self.base.outputs()
    }

    fn input_addresses(&self) -> Vec<String> {
        self.base.input_addresses()
    }

    fn output_addresses(&self) -> Vec<String> {
        self.base.output_addresses()
    }

    fn size(&self) -> usize {
        self.base.size()
    }

    fn payload_data(&self) -> Vec<u8> {
        self.base.payload_data()
    }

    fn to_data_with_subscript_index(&self, subscript_index: Option<u64>) -> Vec<u8> {
        self.base.to_data_with_subscript_index(subscript_index)
    }

    fn set_instant_send_received_with_instant_send_lock(&mut self, instant_send_lock: Option<&InstantSendTransactionLock>) {
        let mut is_signature_verified = false;
        if let Some(lock) = instant_send_lock {
            is_signature_verified = lock.signature_verified;
            self.base.instant_send_received = is_signature_verified;
            self.base.has_unverified_instant_send_lock = !is_signature_verified;
            // we will always need to send this platform
            self.base.instant_send_lock_awaiting_processing = instant_send_lock;
            if !lock.saved {
                lock.save_initial();
            }
        } else {
            self.base.instant_send_received = false;
            self.base.has_unverified_instant_send_lock = false;
            self.base.instant_send_lock_awaiting_processing = None;
        }
    }

    fn is_coinbase_classic_transaction(&self) -> bool {
        self.base.is_coinbase_classic_transaction()
    }

    fn has_non_dust_output_in_wallet(&self, wallet: &Wallet) -> bool {
        self.base.has_non_dust_output_in_wallet(wallet)
    }

    fn to_entity_with_chain_entity(&self, chain_entity: ChainEntity) -> NewTransactionEntity {
        let mut base = self.base.to_entity_with_chain_entity(chain_entity);
        base
    }
}
