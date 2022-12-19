use std::collections::{HashMap, HashSet};
use chrono::NaiveDateTime;
use diesel::{QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::chain::Chain;
use crate::chain::common::ChainType;
use crate::chain::tx::{Transaction, TransactionInput, TransactionOutput, TransactionType};
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::chain::tx::transaction::ITransaction;
use crate::crypto::{UInt128, UInt160, UInt256, UInt384};
use crate::crypto::primitives::utxo::UTXO;
use crate::schema::transactions;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::chain::instant_send_lock::InstantSendLockEntity;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::common::shapeshift::ShapeshiftEntity;
use crate::storage::models::entity::Entity;
use crate::storage::models::tx::transaction_input::{NewTransactionInputEntity, TransactionInputEntity};
use crate::storage::models::tx::transaction_output::{NewTransactionOutputEntity, TransactionOutputEntity};
use crate::util::crypto::shapeshift_outbound_address_for_script;

/// queries:
/// "transactionHash.txHash == %@"
/// "transactionHash.chain = %@"
/// "(ANY outputs.address == %@) || (ANY inputs.localAddress.address = %@)"
/// indexation:
/// "transactionHash.timestamp": DESC
/// ["transactionHash.blockHeight": DESC, "transactionHash.timestamp": DESC]
#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
pub struct TransactionEntity {
    pub id: i32,

    pub hash: UInt256,
    pub block_height: i32,
    pub version: i16,
    pub lock_time: i32,
    pub timestamp: NaiveDateTime,
    pub tx_type: i16,
    // Special Transaction Stuff
    pub special_transaction_version: Option<i16>,
    pub height: Option<i32>,
    pub ip_address: Option<UInt128>,
    pub port: Option<i16>,
    pub provider_mode: Option<i32>,
    pub provider_type: Option<i32>,
    pub reason: Option<i32>,
    pub collateral_outpoint: Option<UTXO>,
    pub operator_reward: Option<i16>,
    pub operator_key: Option<UInt384>,
    pub owner_key_hash: Option<UInt160>,
    pub voting_key_hash: Option<UInt160>,
    pub payload_signature: Option<UInt256>,
    pub script_payout: Option<Vec<u8>>,
    pub quorum_commitment_height: Option<i32>,
    pub mn_list_merkle_root: Option<UInt256>,
    pub llmq_list_merkle_root: Option<UInt256>,
    pub provider_registration_transaction_hash: Option<UInt256>,
    // Relationships
    pub chain_id: i32,
    pub associated_shapeshift_id: Option<i32>,
    pub instant_send_lock_id: Option<i32>,
    // Special Transaction Relationships
    pub local_masternode_id: Option<i32>,
    pub registered_identity_id: Option<i32>,
    pub topped_up_identity_id: Option<i32>,
    pub quorum_id: Option<i32>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[table_name="transactions"]
pub struct NewTransactionEntity {
    pub hash: UInt256,
    pub block_height: i32,
    pub version: i16,
    pub lock_time: i32,
    pub timestamp: NaiveDateTime,
    // Special Transaction Stuff
    pub special_transaction_version: Option<i16>,
    pub height: Option<i32>,
    pub ip_address: Option<UInt128>,
    pub port: Option<i16>,
    pub provider_mode: Option<i16>,
    pub provider_type: Option<i16>,
    pub reason: Option<i32>,
    pub collateral_outpoint: Option<UTXO>,
    pub operator_reward: Option<i16>,
    pub operator_key: Option<UInt384>,
    pub owner_key_hash: Option<UInt160>,
    pub voting_key_hash: Option<UInt160>,
    pub payload_signature: Option<Vec<u8>>,
    pub script_payout: Option<Vec<u8>>,
    pub quorum_commitment_height: Option<i32>,
    pub mn_list_merkle_root: Option<UInt256>,
    pub llmq_list_merkle_root: Option<UInt256>,
    pub provider_registration_transaction_hash: Option<UInt256>,
    // Relationships
    pub chain_id: i32,
    pub associated_shapeshift_id: Option<i32>,
    pub instant_send_lock_id: Option<i32>,
    // Special Transaction Relationships
    pub local_masternode_id: Option<i32>,
    pub registered_identity_id: Option<i32>,
    pub topped_up_identity_id: Option<i32>,
    pub quorum_id: Option<i32>,
}

impl Entity for TransactionEntity {
    type ID = transactions::id;
    type ChainId = transactions::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        transactions::dsl::transactions
    }
}

impl TransactionEntity {
    pub fn update_height_and_timestamps(heights: &HashMap<UInt256, u32>, timestamps: &HashMap<UInt256, u64>, context: &ManagedContext) -> QueryResult<usize> {
        for (hash, height) in heights {
            let predicate = transactions::hash.eq(hash);
            let timestamp = timestamps.get(hash).unwrap();
            let date_time = NaiveDateTime::from_timestamp_opt(timestamp as i64, 0).unwrap();
            let values = (
                transactions::block_height.eq(height),
                transactions::timestamp.eq(date_time)
            );
            if let Err(err) = Self::update(predicate, &values, context) {
                return Err(err);
            }
        }
        Ok(heights.len())
    }

    pub fn get_by_tx_hash(hash: &UInt256, context: &ManagedContext) -> QueryResult<Self> {
        let predicate = transactions::hash.eq(hash);
        Self::any(predicate, context)
    }

    pub fn transactions_for_chain_type(chain_type: ChainType, context: &ManagedContext) -> QueryResult<Vec<TransactionEntity>> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity|
                Self::read(transactions::chain_id.eq(chain_entity.id), context))
    }

    pub fn get_associated_shapeshift(&self, context: &ManagedContext) -> QueryResult<Option<ShapeshiftEntity>> {
        if let Some(shapeshift_id) = self.associated_shapeshift_id {
            match ShapeshiftEntity::get_by_id(shapeshift_id, context) {
                Ok(entity) => Ok(Some(entity)),
                Err(err) => Err(err)
            }
        } else {
            Ok(None)
        }
    }
    pub fn inputs(&self, context: &ManagedContext) -> QueryResult<Vec<TransactionInput>> {
        self.get_inputs(context)
            .and_then(|inputs| inputs.iter().map(|&input|
                TransactionInput::from_entity(input))
                .collect())

    }

    pub fn outputs(&self, context: &ManagedContext) -> QueryResult<Vec<TransactionOutput>> {
        self.get_outputs(context)
            .and_then(|entities|
                entities
                    .iter()
                    .map(|&entity| TransactionOutput::from_entity(entity))
                    .collect())
    }

    pub fn get_inputs(&self, context: &ManagedContext) -> QueryResult<Vec<TransactionInputEntity>> {
        TransactionInputEntity::inputs_for_transaction_id(self.id, context)
    }

    pub fn get_outputs(&self, context: &ManagedContext) -> QueryResult<Vec<TransactionOutputEntity>> {
        TransactionOutputEntity::outputs_for_transaction_id(self.id, context)
    }

    pub fn instant_send_lock(&self, tx_hash: UInt256, transaction_inputs: &Vec<TransactionInput>, chain: &Chain, context: &ManagedContext) -> QueryResult<Option<&InstantSendTransactionLock>> {
        self.get_instant_send_lock(context)
            .and_then(|entity_opt|
                match entity_opt {
                    Some(entity) => Ok(Some(&InstantSendTransactionLock::from_entity(entity, tx_hash, transaction_inputs, chain))),
                    None => Ok(None)
                }
        )
    }

    pub fn get_instant_send_lock(&self, context: &ManagedContext) -> QueryResult<Option<InstantSendLockEntity>> {
        if let Some(lock_id) = self.instant_send_lock_id {
            match InstantSendLockEntity::get_by_id(lock_id, context) {
                Ok(entity) => Ok(Some(entity)),
                Err(err) => Err(err)
            }
        } else {
            Ok(None)
        }
    }

    pub fn count_transactions_for_chain_type(chain_type: ChainType, context: &ManagedContext) -> QueryResult<i64> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity|
                Self::count(transactions::chain_id.eq(chain_entity.id), context))
    }

    pub fn count_transactions_for_hash(tx_hash: &UInt256, context: &ManagedContext) -> QueryResult<i64> {
        Self::count(transactions::hash.eq(tx_hash), context)
    }

    pub fn count_transactions_for_type(r#type: TransactionType, context: &ManagedContext) -> QueryResult<i64> {
        Self::count(transactions::tx_type.eq(r#type.into()), context)
    }

    pub fn delete_with_tx_hash(tx_hash: &UInt256, context: &ManagedContext) -> QueryResult<usize> {
        Self::delete_by(transactions::hash.eq(tx_hash), context)
    }

    fn init_output_entity(transaction: &dyn ITransaction, transaction_id: i32, output: &TransactionOutput, index: i32, context: &ManagedContext) -> NewTransactionOutputEntity {
        let mut entity = NewTransactionOutputEntity {
            tx_hash: transaction.tx_hash(),
            address: output.address.unwrap_or("".to_string()).as_str(),
            shapeshift_outbound_address: Some(shapeshift_outbound_address_for_script(&output.script, transaction.chain()).unwrap_or("".to_string()).as_str()),
            n: index,
            value: output.amount as i64,
            script: output.script.unwrap_or(vec![]),
            account_id: None,
            local_address_id: None,
            spent_in_input_id: None,
            transaction_id,
        };
        if let Some(addr) = &output.address {
            match AddressEntity::any_id_and_account_id_by_address_and_chain_id(addr, chain_entity.id, context) {
                Ok(aggregate) => {
                    entity.local_address_id = Some(aggregate.0);
                    entity.account_id = Some(aggregate.1);
                },
                Err(err) => {
                    println!("can't retrieve address entities");
                }
            }
        }
        entity
    }

    pub fn save_transaction_for(chain_type: ChainType, transaction: &dyn ITransaction, context: &ManagedContext) -> QueryResult<usize> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity| Self::create_and_get(transaction.to_entity_with_chain_entity(chain_entity), context)
                .and_then(|tx_entity| Self::save_transaction_internals(&tx_entity, transaction, context)))
    }

    fn save_transaction_internals(tx_entity: &TransactionEntity, transaction: &dyn ITransaction, context: &ManagedContext) -> QueryResult<usize> {
        TransactionOutputEntity::create_many(transaction.outputs().iter().enumerate().map(|(index, output)| Self::init_output_entity(transaction, tx_entity.id, output, index as i32, context)).collect(), context)
            .and_then(|tx_output_entities|
                Ok(1 + tx_output_entities.len() + transaction.inputs()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, input)| {
                        let mut new_entity = NewTransactionInputEntity {
                            tx_hash: input.input_hash,
                            n: input.index as i32,
                            sequence: input.sequence as i32,
                            signature: input.signature.unwrap_or(vec![]),
                            local_address_id: None,
                            prev_output_id: None,
                            transaction_id,
                        };
                        if let Ok(output_entity) = TransactionOutputEntity::get_by_tx_hash_and_index(&transaction.tx_hash(), input.index, context) {
                            new_entity.local_address_id = output_entity.local_address_id;
                            TransactionInputEntity::create_and_get(new_entity, context).and_then(|input_entity| output_entity.spent_in_input(input_entity.id, context)).ok()
                        } else {
                            println!("can't retrieve transaction output entity");
                            TransactionInputEntity::create(new_entity, context).ok()
                        }
                    }).sum()))
    }

    pub fn save_transaction_if_need_for(chain_type: ChainType, transaction: &dyn ITransaction, context: &ManagedContext) -> QueryResult<TransactionEntity> {
        ChainEntity::get_chain(chain_type, context)
            .and_then(|chain_entity|
                match Self::get_by_tx_hash(&transaction.tx_hash(), context) {
                    Ok(tx_entity) =>
                        Self::save_transaction_internals(&tx_entity, transaction, context)
                            .and(Ok(tx_entity)),
                    Err(diesel::result::Error::NotFound) =>
                        Self::create_and_get(transaction.to_entity_with_chain_entity(chain_entity), context)
                            .and_then(|tx_entity| Self::save_transaction_internals(&tx_entity, transaction, context))
                            .and(Ok(tx_entity)),
                    Err(err) => panic!("Can't save transaction entity")
                })

    }
}
