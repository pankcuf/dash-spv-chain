use byte::{BytesExt, LE, TryRead};
use byte::ctx::Endian;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use diesel::{Insertable, QueryResult, Table};
use crate::chain::chain::Chain;
use crate::crypto::VarBytes;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};
use crate::storage::models::tx::transaction_output::TransactionOutputEntity;
use crate::util::crypto::address_with_script_pub_key;

#[derive(Clone)]
pub struct TransactionOutput {
    pub amount: u64,
    pub script: Option<Vec<u8>>,
    pub address: Option<String>,
}

impl std::fmt::Debug for TransactionOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionOutput")
            .field("amount", &self.amount)
            .field("script", &self.script.as_ref().unwrap_or(&Vec::<u8>::new()).to_hex())
            .field("address", &self.address)
            .finish()
    }
}

impl<'a> TryRead<'a, Endian> for TransactionOutput {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let amount = bytes.read_with::<u64>(offset, LE)?;
        let script = match bytes.read_with::<VarBytes>(offset, LE) {
            Ok(data) => Some(data.1.to_vec()),
            Err(_err) => None,
        };
        let output = TransactionOutput {
            amount,
            script,
            address: None,
        };
        Ok((output, *offset))
    }
}

impl EntityConvertible for TransactionOutput {
    fn to_entity<T, U>(&self) -> U where T: Table, diesel::query_source::FromClause: QueryFragment<Sqlite>, U: Insertable<T>, diesel::insertable::Values: IValues {
        todo!()
    }

    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>> where T: Table, V: AsChangeset<Target=T> {
        todo!()
    }

    fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self> {
        todo!()
    }
}

impl TransactionOutput {
    pub(crate) fn from_entity(entity: TransactionOutputEntity) -> Self {
        // todo: do we need to restore address with addressWithScriptPubKey?
        // if (!entity.address && entity.script) {
        //     address = [NSString addressWithScriptPubKey:script onChain:self.chain];
        // }
        // DSTransactionOutput *transactionOutput = [DSTransactionOutput transactionOutputWithAmount:amount address:address outScript:script onChain:self.chain];
        // [self.mOutputs addObject:transactionOutput];
        Self {
            amount: entity.value as u64,
            script: Some(entity.script),
            address: Some(entity.address)
        }
    }
}

impl TransactionOutput {
    pub fn new(amount: u64, script: Option<Vec<u8>>, address: Option<String>) -> Self {
        Self {
            amount,
            script,
            address
        }
    }

    pub fn from_script(amount: u64, script: Vec<u8>, chain: &Chain) -> Self {
        Self::new(amount, Some(script), address_with_script_pub_key(&script, chain))
    }
}

