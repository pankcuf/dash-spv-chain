use byte::{BytesExt, LE, TryRead};
use byte::ctx::Endian;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use diesel::{Insertable, QueryResult, Table};
use crate::chain::tx::transaction::ITransaction;
use crate::crypto::{UInt256, VarBytes};
use crate::crypto::primitives::utxo::UTXO;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};
use crate::storage::models::tx::transaction::TransactionEntity;
use crate::storage::models::tx::transaction_input::{NewTransactionInputEntity, TransactionInputEntity};

#[derive(Clone)]
pub struct TransactionInput {
    pub input_hash: UInt256,
    pub index: u32,
    pub script: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub sequence: u32,
}

impl std::fmt::Debug for TransactionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionInput")
            .field("input_hash", &self.input_hash)
            .field("index", &self.index)
            .field(
                "script",
                &self.script.as_ref().unwrap_or(&Vec::<u8>::new()).to_hex(),
            )
            .field(
                "signature",
                &self
                    .signature
                    .as_ref()
                    .unwrap_or(&Vec::<u8>::new())
                    .to_hex(),
            )
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl<'a> TryRead<'a, Endian> for TransactionInput {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let input_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let index = bytes.read_with::<u32>(offset, LE)?;
        let signature = match bytes.read_with::<VarBytes>(offset, LE) {
            Ok(data) => Some(data.1.to_vec()),
            Err(_err) => None,
        };
        let sequence = bytes.read_with::<u32>(offset, LE)?;
        let input = TransactionInput {
            input_hash,
            index,
            script: None,
            signature,
            sequence,
        };
        Ok((input, *offset))
    }
}

impl EntityConvertible for TransactionInput {
    fn to_entity<T, U>(&self) -> U
        where T: Table, diesel::query_source::FromClause: QueryFragment<Sqlite>, U: Insertable<T>, diesel::insertable::Values: IValues {
        todo!()
    }

    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>> where T: Table, V: AsChangeset<Target=T> {
        todo!()
    }

    fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self> {
        todo!()
    }
}

impl TransactionInput {
    pub fn from_entity(entity: TransactionInputEntity) -> Self {
        Self {
            input_hash: entity.tx_hash,
            index: entity.n as u32,
            script: None,
            signature: Some(entity.signature),
            sequence: entity.sequence as u32
        }
    }

    pub fn outpoint(&self) -> UTXO {
        UTXO { hash: self.input_hash, n: self.index }
    }
}
