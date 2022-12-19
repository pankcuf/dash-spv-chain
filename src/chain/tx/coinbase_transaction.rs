use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use diesel::{Insertable, QueryResult, QuerySource, Table};
use diesel::insertable::CanInsertInSingleQuery;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use hashes::{sha256d, Hash};
use crate::chain::chain::Chain;
use crate::chain::tx::{Transaction, TransactionInput, TransactionOutput, TransactionType};
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::chain::tx::transaction::ITransaction;
use crate::chain::wallet::wallet::Wallet;
use crate::consensus::encode::VarInt;
use crate::consensus::Encodable;
use crate::crypto::byte_util::Zeroable;
use crate::crypto::data_ops::DataAppend;
use crate::crypto::UInt256;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};
use crate::storage::models::tx::transaction::NewTransactionEntity;

#[derive(Debug, Clone)]
pub struct CoinbaseTransaction {
    pub base: Transaction,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: UInt256,
    pub merkle_root_llmq_list: Option<UInt256>,
}

impl<'a> TryRead<'a, Endian> for CoinbaseTransaction {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let mut base = bytes.read_with::<Transaction>(offset, endian)?;
        let _extra_payload_size = bytes.read_with::<VarInt>(offset, endian)?;
        let coinbase_transaction_version = bytes.read_with::<u16>(offset, endian)?;
        let height = bytes.read_with::<u32>(offset, endian)?;
        let merkle_root_mn_list = bytes.read_with::<UInt256>(offset, endian)?;
        let merkle_root_llmq_list = if coinbase_transaction_version >= 2 {
            let root = bytes.read_with::<UInt256>(offset, endian)?;
            Some(root)
        } else {
            None
        };
        base.tx_type = TransactionType::Coinbase;
        base.payload_offset = *offset;
        let mut tx = Self {
            base,
            coinbase_transaction_version,
            height,
            merkle_root_mn_list,
            merkle_root_llmq_list,
        };
        tx.base.tx_hash = UInt256::sha256d(&tx.to_data());
        Ok((tx, *offset))
    }
}

impl CoinbaseTransaction {



    pub fn has_found_coinbase(&mut self, hashes: &[UInt256]) -> bool {
        if self.base.tx_hash.is_zero() {
            self.base.tx_hash = UInt256::sha256d(&self.to_data());
        }
        self.has_found_coinbase_internal(self.base.tx_hash, hashes)
    }

    fn has_found_coinbase_internal(&self, coinbase_hash: UInt256, hashes: &[UInt256]) -> bool {
        hashes
            .iter()
            .filter(|&h| coinbase_hash.cmp(h).is_eq())
            .count()
            > 0
    }

    pub fn init_with_coinbase_message(message: &String, payment_addresses: Vec<String>, height: u32, chain: &Chain) -> Self {
        let mut base = Transaction::init_on_chain(chain);
        let tx = Self {
            base,
            coinbase_transaction_version: 0,
            height,
            merkle_root_mn_list: Default::default(),
            merkle_root_llmq_list: None
        };
        base.add_input_hash_with_signature(UInt256::MIN, u32::MAX, None, Some(Vec::<u8>::from_coinbase_message(message, height)), u32::MAX);
        payment_addresses.iter().for_each(|&addr| base.add_output_address(addr, chain.params.base_reward / addr.len()));
        base.tx_hash = UInt256::sha256d(&tx.to_data());
        tx
    }

}

impl EntityConvertible for CoinbaseTransaction {
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

impl ITransaction for CoinbaseTransaction {
    fn chain(&self) -> &Chain {
        self.base.chain()
    }

    fn r#type(&self) -> TransactionType {
        TransactionType::Coinbase
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
        self.base.size() + VarInt(self.payload_data().len() as u64).len()
    }

    fn payload_data(&self) -> Vec<u8> {
        let mut writer = Vec::<u8>::new();
        self.coinbase_transaction_version.enc(&mut writer);
        self.height.enc(&mut writer);
        self.merkle_root_mn_list.enc(&mut writer);
        if self.coinbase_transaction_version >= 2 {
            self.merkle_root_llmq_list.unwrap().enc(&mut writer);
        }
        writer
    }

    fn to_data_with_subscript_index(&self, subscript_index: Option<u64>) -> Vec<u8> {
        let mut writer = Transaction::data_with_subscript_index_static(
            subscript_index,
            self.base.version,
            self.base.tx_type,
            &self.base.inputs,
            &self.base.outputs,
            self.base.lock_time,
        );
        self.payload_data().enc(&mut writer);
        writer
    }

    fn set_instant_send_received_with_instant_send_lock(&mut self, instant_send_lock: Option<&InstantSendTransactionLock>) {
        self.base.set_instant_send_received_with_instant_send_lock(instant_send_lock);
    }

    fn is_coinbase_classic_transaction(&self) -> bool {
        self.base.is_coinbase_classic_transaction()
    }

    fn has_non_dust_output_in_wallet(&self, wallet: &Wallet) -> bool {
        self.base.has_non_dust_output_in_wallet()
    }

    fn to_entity_with_chain_entity(&self, chain_entity: ChainEntity) -> NewTransactionEntity {
        let mut base = self.base.to_entity_with_chain_entity(chain_entity);
        base.special_transaction_version = Some(self.coinbase_transaction_version as i16);
        base.height = Some(self.height as i32);
        base.mn_list_merkle_root = Some(self.merkle_root_mn_list);
        base
    }
}

// todo: migrate to custom trait which allows passing of custom context, like Chain etc.
impl<'a> TryRead<'a, Endian> for CoinbaseTransaction {
    fn try_read(bytes: &'a [u8], ctx: Endian) -> byte::Result<(Self, usize)> {
        let (mut base, mut offset) = Transaction::try_read(bytes, ctx)?;
        base.tx_type = TransactionType::Coinbase;
        let _extra_payload_size = bytes.read_with::<VarInt>(&mut offset, byte::LE)?;
        let coinbase_transaction_version = bytes.read_with::<u16>(&mut offset, byte::LE)?;
        let height = bytes.read_with::<u32>(&mut offset, byte::LE)?;
        let merkle_root_mn_list = bytes.read_with::<UInt256>(&mut offset, byte::LE)?;
        // todo: check maybe better use version >= 2 here
        let merkle_root_llmq_list = if coinbase_transaction_version == 2 {
            Some(bytes.read_with::<UInt256>(&mut offset, byte::LE)?)
        } else {
            None
        };
        base.payload_offset = *offset;
        let mut tx = Self {
            base,
            coinbase_transaction_version,
            height,
            merkle_root_mn_list,
            merkle_root_llmq_list
        };
        tx.base.tx_hash = UInt256::sha256d(&tx.to_data());
        Ok((tx, *offset))

    }
}
