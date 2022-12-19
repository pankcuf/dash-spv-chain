use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use diesel::{Insertable, QueryResult, QuerySource, Table};
use diesel::insertable::CanInsertInSingleQuery;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use crate::chain::chain::Chain;
use crate::chain::extension::transactions::Transactions;
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::{UInt128, UInt256, UInt768, VarBytes};
use crate::tx::transaction::ITransaction;
use crate::chain::tx::Transaction;
use crate::chain::tx::provider_registration_transaction::ProviderRegistrationTransaction;
use crate::chain::tx::transaction::{ITransaction, SIGHASH_ALL};
use crate::chain::tx::transaction_input::TransactionInput;
use crate::chain::tx::transaction_output::TransactionOutput;
use crate::chain::tx::transaction_type::TransactionType;
use crate::chain::wallet::wallet::Wallet;
use crate::crypto::byte_util::{AsBytesVec, Zeroable};
use crate::crypto::data_ops::DataAppend;
use crate::keys::bls_key::BLSKey;
use crate::keys::key::IKey;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};
use crate::util::address_with_script_pub_key;
use crate::util::crypto::address_with_script_pub_key;

pub struct ProviderUpdateServiceTransaction {
    pub base: Transaction,
    pub provider_update_service_transaction_version: u16,
    pub provider_registration_transaction_hash: UInt256,
    pub ip_address: UInt128, // v6, but only v4 supported
    pub port: u16,
    pub script_payout: Vec<u8>,
    pub inputs_hash: UInt256,
    pub payload_signature: Vec<u8>,
    provider_registration_transaction: Option<&'static ProviderRegistrationTransaction>,
}

impl EntityConvertible for ProviderUpdateServiceTransaction {
    fn to_entity<T, U>(&self) -> U where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite>, U: Insertable<T>, diesel::insertable::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite> {
        todo!()
    }

    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>> where T: Table, V: AsChangeset<Target=T> {
        todo!()
    }

    fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self> {
        todo!()
    }
}

impl ITransaction for ProviderUpdateServiceTransaction {
    fn chain(&self) -> &Chain {
        self.base.chain()
    }
    fn r#type(&self) -> TransactionType {
        TransactionType::ProviderUpdateService
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
        if !self.tx_hash().is_zero() {
            return self.to_data().len();
        }
        self.base.size() + VarInt(self.payload_data().len() as u64) + self.base_payload_data().len() + 96
    }

    fn payload_data(&self) -> Vec<u8> {
        let mut writer: Vec<u8> = Vec::new();
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
        self.base.has_non_dust_output_in_wallet()
    }
}

impl ProviderUpdateServiceTransaction {
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
        assert!(self.provider_registration_transaction().is_some(), "We need a provider registration transaction");
        //[DSBLSKey keyWithPublicKey:self.providerRegistrationTransaction.operatorKey useLegacy:[self.chain useLegacyBLS]]
        // todo: check use_legacy_bls has taken from appropriate place
        let key = BLSKey::key_with_public_key(&self.provider_registration_transaction().unwrap().operator_key, self.chain().use_legacy_bls());
        key.verify(self.payload_hash().as_bytes_vec(), &self.payload_signature)
    }

    pub fn sign_payload_with_key(&mut self, key: BLSKey) {
        self.payload_signature = key.sign(&self.payload_data_for_hash())
    }

    pub fn payout_address(&mut self) -> Option<String> {
        if let Some(tx) = self.provider_registration_transaction() {
            if !self.script_payout.is_empty() {
                return address_with_script_pub_key(&self.script_payout, tx.chain());
            }
        }
        None // no payout address
    }

    pub fn base_payload_data(&self) -> Vec<u8> {
        let mut writer: Vec<u8> = Vec::new();
        self.provider_update_service_transaction_version.enc(&mut writer);
        self.provider_registration_transaction_hash.enc(&mut writer);
        self.ip_address.enc(&mut writer);
        self.port.swap_bytes().enc(&mut writer);
        VarInt(self.script_payout.len() as u64).enc(&mut writer);
        self.script_payout.enc(&mut writer);
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

// todo: migrate to custom trait which allows passing of custom context, like Chain etc.
impl<'a> TryRead<'a, Endian> for ProviderUpdateServiceTransaction {
    fn try_read(bytes: &'a [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let (mut base, mut offset) = Transaction::try_read(bytes, ctx)?;
        base.tx_type = TransactionType::ProviderUpdateService;
        let _extra_payload_size = bytes.read_with::<VarInt>(&mut offset, byte::LE)?;
        let provider_update_service_transaction_version = bytes.read_with::<u16>(&mut offset, byte::LE)?;
        let provider_registration_transaction_hash = bytes.read_with::<UInt256>(&mut offset, byte::LE)?;
        let ip_address = bytes.read_with::<UInt128>(&mut offset, byte::LE)?;
        // // todo: choose one way of BE vs swap_bytes()
        let port = bytes.read_with::<u16>(&mut offset, byte::BE)?;
        let script_payout = bytes.read_with::<VarBytes>(&mut offset, byte::LE)?.1.to_vec();
        let inputs_hash = bytes.read_with::<UInt256>(&mut offset, byte::LE)?;
        let payload_signature = bytes.read_with::<UInt768>(&mut offset, byte::LE)?;
        base.payload_offset = *offset;
        let mut tx = Self {
            base,
            provider_update_service_transaction_version,
            provider_registration_transaction_hash,
            ip_address,
            port,
            script_payout,
            inputs_hash,
            payload_signature: payload_signature.0.to_vec(),
            provider_registration_transaction: None
        };
        // // todo verify inputs hash
        assert_eq!(tx.payload_data().len(), *offset, "Payload length doesn't match ");
        tx.base.tx_hash = UInt256::sha256d(&tx.to_data());
        Ok((tx, *offset))
    }
}
