use byte::{BytesExt, TryRead};
use crate::chain::chain::Chain;
use crate::chain::ext::transactions::Transactions;
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::chain::tx::provider_registration_transaction::ProviderRegistrationTransaction;
use crate::crypto::{UInt256, UInt768};
use crate::chain::tx::transaction::{ITransaction, SIGHASH_ALL};
use crate::chain::tx::Transaction;
use crate::chain::tx::transaction_input::TransactionInput;
use crate::chain::tx::transaction_output::TransactionOutput;
use crate::chain::tx::transaction_type::TransactionType;
use crate::chain::wallet::wallet::Wallet;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::byte_util::{AsBytesVec, Zeroable};
use crate::derivation::derivation_path::IDerivationPath;
use crate::util::data_append::DataAppend;
use crate::keys::bls_key::BLSKey;
use crate::keys::key::IKey;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::tx::transaction::NewTransactionEntity;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderUpdateRevocationTransaction {
    pub base: Transaction,
    pub provider_registration_transaction_hash: UInt256,
    pub provider_update_revocation_transaction_version: u16,
    pub reason: u16,
    pub inputs_hash: UInt256,

    pub payload_signature: Vec<u8>,

    pub provider_registration_transaction: Option<&'static ProviderRegistrationTransaction>,
}

impl ITransaction for ProviderUpdateRevocationTransaction {
    fn chain(&self) -> &Chain {
        self.base.chain()
    }

    fn r#type(&self) -> TransactionType {
        TransactionType::ProviderUpdateRevocation
    }

    fn block_height(&self) -> u32 {
        self.base.block_height()
    }

    fn tx_hash(&self) -> UInt256 {
        self.base.tx_hash()
    }

    fn tx_lock_time(&self) -> u32 {
        self.base.tx_lock_time()
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
        if !self.tx_hash().is_zero() {
            return self.to_data().len();
        }
        self.base.size() + VarInt(self.payload_data().len() as u64).len() + self.base_payload_data().len() + 96
    }

    fn payload_data(&self) -> Vec<u8> {
        let mut writer = Vec::<u8>::new();
        self.base_payload_data().enc(&mut writer);
        self.payload_signature.enc(&mut writer);
        writer
    }

    fn payload_data_for_hash(&self) -> Vec<u8> {
        self.base_payload_data()
    }

    fn to_data_with_subscript_index(&self, subscript_index: Option<u64>) -> Vec<u8> {
        let mut data = self.base.to_data_with_subscript_index(subscript_index);
        data.append_counted_data(self.payload_data());
        if subscript_index.is_some() {
            SIGHASH_ALL.enc(&mut data);
        }
        data
    }

    fn set_instant_send_received_with_instant_send_lock(&mut self, instant_send_lock: Option<&InstantSendTransactionLock>) {
        self.base.set_instant_send_received_with_instant_send_lock(instant_send_lock)
    }

    fn is_coinbase_classic_transaction(&self) -> bool {
        self.base.is_coinbase_classic_transaction()
    }

    fn has_set_inputs_and_outputs(&mut self) {
        self.update_inputs_hash();
    }

    fn has_non_dust_output_in_wallet(&self, wallet: &Wallet) -> bool {
        self.base.has_non_dust_output_in_wallet(wallet)
    }

    fn set_initial_persistent_attributes_in_context(&mut self, context: &ManagedContext) -> bool {
        todo!()
    }

    fn to_entity_with_chain_entity(&self, chain_entity: ChainEntity) -> NewTransactionEntity {
        todo!()
    }

    fn trigger_updates_for_local_references(&self) {
        if let Some(mut local_masternode) = self.chain().masternode_manager().local_masternode_having_provider_registration_transaction_hash(&self.provider_registration_transaction_hash) {
            local_masternode.update_with_update_revocation_transaction(self, true);
        }
    }

    fn load_blockchain_identities_from_derivation_paths(&mut self, derivation_paths: Vec<&dyn IDerivationPath>) {
        self.base.load_blockchain_identities_from_derivation_paths(derivation_paths)
    }
}

impl ProviderUpdateRevocationTransaction {

    pub fn provider_registration_transaction(&mut self) -> Option<&ProviderRegistrationTransaction> {
        if let Some(tx) = &self.provider_registration_transaction {
            Some(tx)
        } else {
            let tx = self.chain().transaction_for_hash(&self.provider_registration_transaction_hash);
            self.provider_registration_transaction = tx;
            tx
        }
    }

    pub fn set_provider_registration_transaction_hash(&mut self, hash: UInt256) {
        self.provider_registration_transaction_hash = hash;
        if self.provider_registration_transaction.is_none() {
            self.provider_registration_transaction = self.chain().transaction_for_hash(&self.provider_registration_transaction_hash);
        }
    }

    pub fn payload_hash(&self) -> UInt256 {
        UInt256::sha256d(&self.payload_data_for_hash())
    }

    pub fn check_payload_signature(&mut self) -> bool {
        assert!(self.provider_registration_transaction.is_some(), "We need a provider registration transaction");
        // todo: check use_legacy_bls has taken from appropriate place
        let key = BLSKey::key_with_public_key(self.provider_registration_transaction().unwrap().operator_key.clone(), self.chain().use_legacy_bls());
        self.check_payload_signature_with_key(&key)
    }

    pub fn check_payload_signature_with_key(&mut self, key: &BLSKey) -> bool {
        // todo: where migrate to bytes to avoid Vec<u8> <--> UInt256 conversion?
        key.verify(self.payload_hash().as_bytes_vec(), &self.payload_signature)
    }

    pub fn sign_payload_with_key(&mut self, private_key: &BLSKey) {
        // ATTENTION If this ever changes from ECDSA, change the max signature size defined above
        self.payload_signature = private_key.sign_data(&self.payload_data_for_hash()).0.to_vec();
    }

    pub fn base_payload_data(&self) -> Vec<u8> {
        let mut writer = Vec::<u8>::new();
        self.provider_update_revocation_transaction_version.enc(&mut writer);
        self.provider_registration_transaction_hash.enc(&mut writer);
        self.reason.enc(&mut writer);
        self.inputs_hash.enc(&mut writer);
        writer
    }

    pub fn update_inputs_hash(&mut self) {
        let mut writer = Vec::<u8>::new();
        self.inputs().iter().for_each(|input| {
            input.input_hash.enc(&mut writer);
            input.index.enc(&mut writer);
        });
        self.inputs_hash = UInt256::sha256d(&writer);
    }

}

impl<'a> TryRead<'a, &Chain> for ProviderUpdateRevocationTransaction {
    fn try_read(bytes: &'a [u8], chain: &Chain) -> byte::Result<(Self, usize)> {
        let (mut base, mut offset) = Transaction::try_read(bytes, chain)?;
        base.tx_type = TransactionType::ProviderUpdateRevocation;
        let _extra_payload_size = bytes.read_with::<VarInt>(&mut offset, byte::LE)?;
        let provider_update_revocation_transaction_version = bytes.read_with::<u16>(&mut offset, byte::LE)?;
        let provider_registration_transaction_hash = bytes.read_with::<UInt256>(&mut offset, byte::LE)?;
        let reason = bytes.read_with::<u16>(&mut offset, byte::LE)?;
        let inputs_hash = bytes.read_with::<UInt256>(&mut offset, byte::LE)?;
        let payload_signature = bytes.read_with::<UInt768>(&mut offset, byte::LE)?;
        base.payload_offset = offset;
        let mut tx = Self {
            base,
            provider_registration_transaction_hash,
            provider_update_revocation_transaction_version,
            reason,
            inputs_hash,
            payload_signature: payload_signature.0.to_vec(),
            provider_registration_transaction: None
        };
        // todo verify inputs hash
        assert_eq!(tx.payload_data().len(), offset, "Payload length doesn't match ");
        tx.base.tx_hash = UInt256::sha256d(&tx.to_data());
        Ok((tx, offset))
    }
}
