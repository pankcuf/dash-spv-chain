use std::cmp;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::Hasher;
use std::intrinsics::roundf64;
use byte::ctx::Endian;
use byte::{BytesExt, LE, TryRead};
use chrono::NaiveDateTime;
use diesel::{Insertable, QueryResult, QuerySource, Table};
use diesel::insertable::CanInsertInSingleQuery;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::sqlite::Sqlite;
use hashes::hex::ToHex;
use hashes::{Hash, sha256d};
use secp256k1::rand::{Rng, thread_rng};
use crate::blockdata::opcodes::all::{OP_EQUALVERIFY, OP_RETURN};
use crate::chain::chain::Chain;
use crate::chain::extension::accounts::Accounts;
use crate::chain::extension::transactions::Transactions;
use crate::chain::params::{TX_FEE_PER_B, TX_FEE_PER_INPUT, TX_INPUT_SIZE, TX_MIN_OUTPUT_AMOUNT, TX_OUTPUT_SIZE};
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::chain::tx::transaction_input::TransactionInput;
use crate::chain::tx::transaction_output::TransactionOutput;
use crate::chain::tx::transaction_persistence_status::TransactionPersistenceStatus;
use crate::chain::tx::transaction_type::TransactionType;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::wallet::Wallet;
use crate::consensus::encode::VarInt;
use crate::consensus::Encodable;
use crate::crypto::{UInt256, VarBytes};
use crate::crypto::byte_util::{AsBytes, AsBytesVec, Zeroable};
use crate::crypto::data_ops::{Data, DataAppend};
use crate::derivation::derivation_path::{DerivationPathKind, IDerivationPath};
use crate::derivation::incoming_funds_derivation_path::IncomingFundsDerivationPath;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::keys::key::IKey;
use crate::platform::identity::identity::Identity;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::common::shapeshift::{ShapeshiftAddressStatus, ShapeshiftEntity};
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates};
use crate::storage::models::tx::transaction::{NewTransactionEntity, TransactionEntity};
use crate::storage::models::tx::transaction_input::NewTransactionInputEntity;
use crate::storage::models::tx::transaction_output::NewTransactionOutputEntity;
use crate::util::crypto::{address_with_public_key_data, address_with_script_pub_key, address_with_script_sig, shapeshift_outbound_address_for_script, shapeshift_outbound_address_force_script};

// block height indicating transaction is unconfirmed
pub const TX_UNCONFIRMED: i32 = i32::MAX;

pub static SIGHASH_ALL: u32 = 1;
pub static TX_VERSION: u32 = 0x00000001;
pub static SPECIAL_TX_VERSION: u32 = 0x00000003;
pub static TX_LOCKTIME: u32 = 0x00000000;
pub static TXIN_SEQUENCE: u32 = u32::MAX;

pub const MAX_ECDSA_SIGNATURE_SIZE: usize = 75;


pub trait ITransaction: EntityConvertible {
    fn chain(&self) -> &Chain;
    fn accounts(&self) -> Vec<&Account> {
        self.chain().accounts_that_can_contain_transaction(self)
    }
    fn first_account(&self) -> Option<&Account> {
        self.chain().first_account_that_can_contain_transaction(self)
    }

    fn r#type(&self) -> TransactionType;
    fn block_height(&self) -> u32;
    fn tx_hash(&self) -> UInt256;
    fn inputs(&self) -> Vec<TransactionInput>;
    fn outputs(&self) -> Vec<TransactionOutput>;
    fn input_addresses(&self) -> Vec<String>;
    fn output_addresses(&self) -> Vec<String>;

    fn size(&self) -> usize;

    fn payload_data(&self) -> Vec<u8> {
        vec![]
    }
    fn payload_data_for_hash(&self) -> Vec<u8> {
        vec![]
    }

    fn to_data(&self) -> Vec<u8> {
        self.to_data_with_subscript_index(None)
    }
    fn to_data_with_subscript_index(&self, subscript_index: Option<u64>) -> Vec<u8>;

    fn set_instant_send_received_with_instant_send_lock(&mut self, instant_send_lock: Option<&InstantSendTransactionLock>);
    fn is_coinbase_classic_transaction(&self) -> bool;
    fn has_set_inputs_and_outputs(&self) {}
    fn has_non_dust_output_in_wallet(&self, wallet: &Wallet) -> bool;

    fn transaction_type_requires_inputs(&self) -> bool {
        self.r#type().requires_inputs()
    }
    fn to_entity_with_chain_entity(&self, chain_entity: ChainEntity) -> NewTransactionEntity;
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u32,
    pub version: u16,
    // todo: avoid option here
    pub tx_hash: UInt256,
    pub tx_type: TransactionType,
    pub payload_offset: usize,
    pub block_height: u32,
    pub timestamp: u64,
    pub instant_send_lock_awaiting_processing: Option<&'static InstantSendTransactionLock>,
    associated_shapeshift: Option<ShapeshiftEntity>,
    pub(crate) instant_send_received: bool,
    pub(crate) has_unverified_instant_send_lock: bool,
    persistence_status: TransactionPersistenceStatus,

    pub chain: &'static Chain,

    source_identities: HashSet<Identity>,
    destination_identities: HashSet<Identity>,
    confirmed: bool,
}

impl PartialEq<Self> for dyn ITransaction {
    fn eq(&self, other: &Self) -> bool {
        self == other || self.tx_hash() == other.tx_hash()
    }
}

impl std::hash::Hash for Transaction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.tx_hash().as_bytes())
    }
}

impl EntityConvertible for Transaction {
    fn to_entity<T, U>(&self) -> U
        where
            T: Table + QuerySource,
            T::FromClause: QueryFragment<Sqlite>,
            U: Insertable<T>, diesel::insertable::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite> {

        NewTransactionEntity {
            hash: self.tx_hash,
            block_height: self.block_height as i32,
            version: self.version as i16,
            lock_time: self.lock_time as i32,
            timestamp: NaiveDateTime::from_timestamp_opt(self.timestamp as i64, 0).unwrap(),
            associated_shapeshift_id: self.associated_shapeshift.and_then(|shapeshift| Some(shapeshift.id)),
            ..Default::default()
        }
    }

    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>> where T: Table, V: AsChangeset<Target=T> {
        todo!()
    }

    fn from_entity<T: Entity>(entity: &TransactionEntity, context: &ManagedContext) -> QueryResult<Self> {
        ChainEntity::chain_by_id(entity.chain_id, context)
            .and_then(|chain| entity.get_associated_shapeshift(context)
                .and_then(|shapeshift_entity| entity.inputs(context)
                    .and_then(|inputs| entity.outputs(context)
                        .and_then(|outputs| entity.instant_send_lock(entity.hash, &inputs, &chain, context)
                            .and_then(|instant_send_lock| Ok(
                                Self::init_with(
                                    entity.version as u16,
                                    entity.lock_time as u32,
                                    inputs,
                                    outputs,
                                    entity.hash,
                                    entity.block_height as u32,
                                    entity.timestamp.timestamp() as u64,
                                    shapeshift_entity,
                                    instant_send_lock
                                )))))))
    }
}

impl ITransaction for Transaction {
    fn chain(&self) -> &Chain {
        self.chain
    }
    fn r#type(&self) -> TransactionType {
        //TransactionType::Classic
        self.tx_type
    }

    fn block_height(&self) -> u32 {
        self.block_height
    }

    fn tx_hash(&self) -> UInt256 {
        self.tx_hash
    }

    fn inputs(&self) -> Vec<TransactionInput> {
        self.inputs.clone()
    }

    fn outputs(&self) -> Vec<TransactionOutput> {
        self.outputs.clone()
    }

    fn input_addresses(&self) -> Vec<String> {
        // TODO: check may be it worth to keep index with Option<String>
        self.inputs.iter().filter_map(|input| {
            if let Some(script) = &input.script {
                address_with_script_pub_key(script, self.chain())
            } else {
                address_with_script_sig(&input.signature, self.chain())
            }
        }).collect()
    }

    fn output_addresses(&self) -> Vec<String> {
        // TODO: check may be it worth to keep index with Option<String>
        self.outputs.iter().filter_map(|output| output.address.clone()).collect()
    }

    /// size in bytes if signed, or estimated size assuming compact pubkey sigs
    fn size(&self) -> usize {
        if !self.tx_hash.is_zero() {
            // todo: check size() is properly overriden according to 'their' to_data
            return self.to_data().len();
        }
        let input_count = self.inputs.len() as u32;
        let output_count = self.outputs.len() as u32;
        return 8 + VarInt(input_count as u64).len() + VarInt(output_count as u64).len() +
            TX_INPUT_SIZE * input_count + TX_OUTPUT_SIZE * output_count;
    }

    fn to_data_with_subscript_index(&self, subscript_index: Option<u64>) -> Vec<u8> {
        Self::data_with_subscript_index_static(
            subscript_index,
            self.version,
            self.tx_type,
            &self.inputs,
            &self.outputs,
            self.lock_time,
        )
    }

    fn set_instant_send_received_with_instant_send_lock(&mut self, instant_send_lock: Option<&InstantSendTransactionLock>) {
        if let Some(lock) = instant_send_lock {
            let is_signature_verified = lock.signature_verified;
            self.instant_send_received = is_signature_verified;
            self.has_unverified_instant_send_lock = !is_signature_verified;
            if is_signature_verified {
                self.instant_send_lock_awaiting_processing = instant_send_lock;
            }
            if !lock.saved {
                lock.save_initial();
            }
        }
    }

    fn is_coinbase_classic_transaction(&self) -> bool {
        if self.inputs.len() == 1 {
            let first_input = self.inputs.first().unwrap();
            if first_input.input_hash.is_zero() && first_input.index == u32::MAX {
                return true;
            }
        }
        return false;
    }

    /// Info
    fn has_non_dust_output_in_wallet(&self, wallet: &Wallet) -> bool {
        self.outputs.iter().find(|output|
            output.amount > TX_MIN_OUTPUT_AMOUNT && wallet.contains_address(output.address.clone()))
            .is_some()
    }

    fn to_entity_with_chain_entity(&self, chain_entity: ChainEntity) -> NewTransactionEntity {
        NewTransactionEntity {
            hash: self.tx_hash,
            block_height: self.block_height as i32,
            version: self.version as i16,
            lock_time: self.lock_time as i32,
            timestamp: NaiveDateTime::from_timestamp_opt(self.timestamp as i64, 0).unwrap(),
            chain_id: chain_entity.id,
            associated_shapeshift_id: self.associated_shapeshift.and_then(|sh| Some(sh.id)).or(None),
            ..Default::default()
        }
    }
}

impl Transaction {
    pub fn init_on_chain(chain: &Chain) -> Self {
        Self {
            chain,
            version: TX_VERSION as u16,
            lock_time: TX_LOCKTIME,
            block_height: TX_UNCONFIRMED as u32,
            ..Default::default()
        }
    }

    pub fn init_with(
        version: u16,
        lock_time: u32,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        tx_hash: UInt256,
        block_height: u32,
        timestamp: u64,
        associated_shapeshift: Option<ShapeshiftEntity>,
        instant_send_lock: Option<&InstantSendTransactionLock>) -> Self {
        let mut s = Self {
            inputs,
            outputs,
            lock_time,
            version,
            timestamp,
            tx_hash,
            block_height,
            instant_send_lock_awaiting_processing: instant_send_lock,
            associated_shapeshift,
            persistence_status: TransactionPersistenceStatus::Saved,
            ..Default::default()
        };
        s.set_instant_send_received_with_instant_send_lock(instant_send_lock);
        s
    }


    pub fn data_with_subscript_index_static(
        subscript_index: Option<u64>,
        version: u16,
        tx_type: TransactionType,
        inputs: &[TransactionInput],
        outputs: &[TransactionOutput],
        lock_time: u32,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let inputs_len = inputs.len();
        let outputs_len = outputs.len();
        let for_sig_hash = (tx_type == TransactionType::Classic || tx_type == TransactionType::CreditFunding) && subscript_index.is_some();
        *offset += version.enc(&mut buffer);
        *offset += tx_type.raw_value().enc(&mut buffer);
        *offset += VarInt(inputs_len as u64).enc(&mut buffer);
        (0..inputs_len).into_iter().for_each(|i| {
            let input = &inputs[i];
            *offset += input.input_hash.enc(&mut buffer);
            *offset += input.index.enc(&mut buffer);
            if subscript_index.is_none() && input.signature.is_some() {
                *offset += input
                    .signature
                    .as_ref()
                    .unwrap()
                    .enc(&mut buffer)
            } else if subscript_index.is_some() && subscript_index.unwrap() == i as u64 && input.script.is_some() {
                *offset += input
                    .script
                    .as_ref()
                    .unwrap()
                    .enc(&mut buffer)
            } else {
                *offset += VarInt(0_u64).enc(&mut buffer);
            }
            *offset += input.sequence.enc(&mut buffer);
        });
        *offset += VarInt(outputs_len as u64)
            .enc(&mut buffer);
        (0..outputs_len).into_iter().for_each(|i| {
            let output = &outputs[i];
            *offset += output.amount.enc(&mut buffer);
            if let Some(script) = &output.script {
                *offset += script.enc(&mut buffer)
            }
        });
        *offset += lock_time.enc(&mut buffer);
        if for_sig_hash {
            *offset += SIGHASH_ALL.enc(&mut buffer);
        }
        buffer
    }
}

impl Transaction {

    pub fn standard_fee(&self) -> u64 {
        TX_FEE_PER_B * self.size()
    }

    pub fn standard_instant_fee(&self) -> u64 {
        TX_FEE_PER_INPUT * self.inputs.len()
    }

    pub fn is_credit_funding_transaction(&self) -> bool {
        self.outputs.iter().filter(|o| {
            if let Some(s) = &o.script {
                if s[0] == OP_RETURN.into_u8() && s.len() == 22 {
                    return true;
                }
            }
            false
        }).count() > 0
    }
}

impl Transaction {

    pub fn shapeshift_outbound_address(&self) -> Option<String> {
        self.outputs.iter().find_map(|output| shapeshift_outbound_address_for_script(&output.script, self.chain))
    }

    pub fn shapeshift_outbound_address_force_script(&self) -> Option<String> {
        self.outputs.iter().find_map(|output| shapeshift_outbound_address_force_script(&output.script))
    }
}

impl Transaction {

    fn amount_sent(&self) -> u64 {
        self.inputs.iter().map(|input| {
            if let Some(tx) = self.chain.transaction_for_hash(&input.input_hash) {
                let n = input.index as usize;
                let outputs = tx.outputs();
                if n < outputs.len() {
                    if let Some(output) = outputs.get(n) {
                        if let Some(acc) = self.chain.first_account_that_can_contain_transaction(&tx) {
                            if acc.contains_address(output.address.clone()) {
                                return Some(output.amount);
                            }
                        }
                    }
                }
            }
            None
        }).sum()
    }

    // checks if all signatures exist, but does not verify them
    pub fn is_signed(&self) -> bool {
        let mut is_signed = true;
        for input in self.inputs {
            let input_is_signed = input.signature.is_some();
            is_signed &= input_is_signed;
            if !input_is_signed {
                break;
            }
        }
        is_signed
    }

    pub fn add_input_hash(&mut self, input_hash: UInt256, index: u32, script: Option<Vec<u8>>) {
        self.add_input_hash_with_signature(input_hash, index, script, None, TXIN_SEQUENCE)
    }

    pub fn add_input_hash_with_signature(&mut self, input_hash: UInt256, index: u32, script: Option<Vec<u8>>, signature: Option<Vec<u8>>, sequence: u32) {
        self.inputs.push(TransactionInput {
            input_hash,
            index,
            script,
            signature,
            sequence
        });
    }

    pub fn add_output_address(&mut self, address: String, amount: u64) {
        // todo: check this is equivalent and no need to recalculate address with addressWithScriptPubKey
        self.outputs.push(TransactionOutput {
            amount,
            script: Some(Vec::<u8>::script_pub_key_for_address(&address, self.chain)),
            address: Some(address)
        });
    }

    pub fn add_output_credit_address(&mut self, address: String, amount: u64) {
        self.outputs.push(
            TransactionOutput::from_script(
                amount,
                Vec::<u8>::script_pub_key_for_address(&address, self.chain()),
                self.chain()))
    }

    pub fn add_output_shapeshift_address(&mut self, address: String) {
        self.outputs.push(
            TransactionOutput::from_script(
                0,
                Vec::<u8>::shapeshift_memo_for_address(address),
                self.chain()))
    }

    pub fn add_output_burn_amount(&mut self, amount: u64) {
        self.outputs.push(
            TransactionOutput::from_script(
                amount,
                vec![OP_RETURN.into_u8()],
                self.chain()));
    }

    pub fn add_output_script(&mut self, script: Option<Vec<u8>>, address: Option<String>, amount: u64) {
        self.outputs.push(
            TransactionOutput::new(
                amount,
                script,
                address.or_else(||
                    script.and_then(|script|
                        address_with_script_pub_key(&script, self.chain())))));
    }

    pub fn set_input_address(&self, address: String, index: usize) {
        self.inputs[index].script = Some(Vec::<u8>::script_pub_key_for_address(&address, self.chain()));
    }

    /// fischer-yates shuffle
    pub fn shuffle_output_order(&mut self) {
        // fischer-yates shuffle
        for i in 0..self.outputs.len() {
            let j = thread_rng().gen_range(i..self.outputs.len() - i);
            if i == j {
                continue;
            }
            self.outputs.swap(i, j);
        }
    }

    /**
     * Hashes (in reversed byte-order) are to be sorted in ASC order, lexicographically.
     * If they're match -> the respective indices will be compared, in ASC.
     */
    pub fn sort_inputs_according_to_bip69(&mut self) {
        self.inputs.sort_by(|i1, i2| match i1.input_hash.cmp(&i2.input_hash) {
            Ordering::Equal => match i1.index.cmp(&i2.index) {
                Ordering::Greater => Ordering::Less,
                Ordering::Less => Ordering::Greater,
                Ordering::Equal => Ordering::Equal
            },
            Ordering::Greater => Ordering::Greater,
            Ordering::Less => Ordering::Less
        })
    }

    /**
     * Amounts are to be sorted in ASC.
     * If they're equal -> respective outScripts will be compared lexicographically, in ASC.
     */
    pub fn sort_outputs_according_to_bip69(&mut self) {
        self.outputs.sort_by(|o1, o2| match o1.amount.cmp(&o2.amount) {
            Ordering::Greater => Ordering::Less,
            Ordering::Less => Ordering::Greater,
            Ordering::Equal => match (&o1.script, &o2.script) {
                (Some(script1), Some(script2)) => match script1.cmp(script2) {
                    Ordering::Equal => match script1.len().cmp(&script2.len()) {
                        Ordering::Equal => Ordering::Equal,
                        Ordering::Less => Ordering::Greater,
                        Ordering::Greater => Ordering::Less
                    },
                    Ordering::Less => Ordering::Greater,
                    Ordering::Greater => Ordering::Less
                },
                (None, None) => Ordering::Equal,
                (Some(..), None) => Ordering::Greater,
                (None, Some(..)) => Ordering::Less
            }
        });
    }


    /// Signing

    pub fn sign_with_serialized_private_keys(&mut self, keys: Vec<&String>) -> bool {
        self.sign_with_private_keys(
            keys.iter()
                .filter_map(|serialized_key|
                    ECDSAKey::key_with_private_key(serialized_key, self.chain()))
                .collect())
    }


    pub fn sign_with_private_keys(&mut self, keys: Vec<&ECDSAKey>) -> bool {
        self.sign_with_private_keys_using_addresses(
            keys,
            keys.iter()
                .map(|key| key.address_with_public_key_data(self.chain()))
                .collect())
    }

    pub fn sign_with_preordered_private_keys(&mut self, keys: Vec<&dyn IKey>) -> bool {
        for (i, input) in self.inputs.iter_mut().enumerate() {
            let mut sig = Vec::<u8>::new();
            let data = self.to_data_with_subscript_index(Some(i as u64));
            let hash = UInt256::sha256d(&data);
            if let Some(key) = keys.get(i) {
                let mut s = key.sign(hash.as_bytes_vec());
                if let Some(input_script) = &input.script {
                    let elem = input_script.script_elements();
                    (SIGHASH_ALL as u8).enc(&mut s);
                    sig.append_script_push_data(&s);
                    if elem.len() >= 2 && elem[elem.len() - 2] == OP_EQUALVERIFY {
                        // pay-to-pubkey-hash scriptSig
                        sig.append_script_push_data(key.public_key_data());
                    }
                    input.signature = Some(sig);
                }
            }
        }
        if !self.is_signed() {
            return false;
        }
        self.tx_hash = UInt256::sha256d(&self.to_data());
        true
    }

    pub fn sign_with_private_keys_using_addresses(&mut self, keys: Vec<&dyn IKey>, addresses: Vec<String>) -> bool {
        for (i, input) in self.inputs.iter_mut().enumerate() {
            if let Some(input_script) = &input.script {
                if let Some(addr) = address_with_script_pub_key(input_script, self.chain()) {
                    if let Some(key_idx) = addresses.iter().position(|a| a == addr) {
                        let mut sig = Vec::<u8>::new();
                        let data = self.to_data_with_subscript_index(Some(key_idx as u64));
                        let hash = UInt256::sha256d(&data);
                        if let Some(key) = keys.get(key_idx) {
                            let mut s = key.sign(hash.as_bytes_vec());
                            let elem = input_script.script_elements();
                            (SIGHASH_ALL as u8).enc(&mut s);
                            sig.append_script_push_data(&s);
                            if elem.len() >= 2 && elem[elem.len() - 2] == OP_EQUALVERIFY {
                                // pay-to-pubkey-hash scriptSig
                                sig.append_script_push_data(key.public_key_data());
                            }
                            input.signature = Some(sig);
                        }
                    }
                }
            }
        }
        if !self.is_signed() {
            return false;
        }
        self.tx_hash = UInt256::sha256d(&self.to_data());
        true
    }


    /// Priority (Deprecated)

    // priority = sum(input_amount_in_satoshis*input_age_in_blocks)/size_in_bytes
    pub fn priority_for_amounts(&self, amounts: Vec<u64>, ages: Vec<u64>) -> u64 {
        let mut p = 0u64;
        if amounts.len() != self.inputs.len() || ages.len() != self.inputs.len() || ages.contains(&0) {
            return 0;
        }
        for i in 0..amounts.len() {
            p += amounts[i] * ages[i];
        }
        p / self.size()
    }

    /// Fees

    // returns the fee for the given transaction if all its inputs are from wallet transactions, u64::MAX otherwise
    pub fn fee_used(&self) -> u64 {
        //TODO: This most likely does not work when sending from multiple accounts
        self.first_account().unwrap().fee_for_transaction(self)
    }

    pub fn rounded_fee_cost_per_byte(&self) -> u64 {
        let fee_used = self.fee_used();
        if fee_used == u64::MAX {
            return u64::MAX;
        }
        (fee_used as f64 / self.size() as f64).round() as u64
    }

    pub fn confirmations(&mut self) -> u32 {
        if self.block_height == TX_UNCONFIRMED {
            return 0;
        }
        self.chain.last_terminal_block_height() - self.block_height
    }

    pub fn confirmed(&mut self) -> bool {
        if self.confirmed {
            // because it can't be unconfirmed
            return true;
        }
        if self.block_height == TX_UNCONFIRMED {
            return false;
        }
        let last_height = self.chain().last_sync_block_height;
        if self.block_height > last_height {
            // this should only be possible if and only if we have migrated and kept old transactions.
            return true;
        }
        if last_height - self.block_height > 6 {
            return true;
        }
        self.confirmed = self.chain().block_height_chain_locked(self.block_height);
        self.confirmed
    }


    /// Identities
    pub fn load_blockchain_identities_from_derivation_paths(&mut self, derivation_paths: Vec<&dyn IDerivationPath>) {
        let mut destination_identities = HashSet::new();
        let mut source_identities = HashSet::new();
        for output in self.outputs {
            for derivation_path in derivation_paths {
                if derivation_path.kind() == DerivationPathKind::IncomingFunds && derivation_path.contains_address(output.address.clone()) {
                    let incoming_funds_derivation_path = derivation_path as IncomingFundsDerivationPath;
                    let destination_identity = incoming_funds_derivation_path.contact_destination_blockchain_identity();
                    let source_identity = incoming_funds_derivation_path.contact_source_blockchain_identity();
                    // these need to be inverted since the derivation path is incoming
                    if source_identity.is_some() {
                        destination_identities.insert(source_identity.unwrap());
                    }
                    if destination_identity.is_some() {
                        source_identities.insert(destination_identity.unwrap());
                    }
                }
            }
        }
        self.source_identities.extend(source_identities);
        self.destination_identities.extend(destination_identities);
    }

    pub fn save(&self) {
        self.save_in_context(self.chain.chain_context());
    }

    pub fn save_in_context(&self, context: &ManagedContext) {
        context.perform_block_and_wait(|context| {
            TransactionEntity::save_transaction_if_need_for(self.chain.r#type(), self, context)
                .expect("Error saving transaction");
        });
    }


    pub fn set_initial_persistent_attributes_in_context(&mut self, context: &ManagedContext) -> bool {
        // TODO: impl prepare and commit changes in managed context (to delay insert) or use TransactionEntity::save_transaction_for
        match TransactionEntity::count_transactions_for_hash(&self.tx_hash(), context) {
            Ok(0) => match context.prepare(self.to_entity(), TransactionEntity::create) {
                Ok(1) => true,
                _ => false
            },
            _ => false
        }
    }

    pub fn save_initial(&mut self) -> bool {
        self.save_initial_in_context(self.chain().chain_context())
    }

    pub fn save_initial_in_context(&mut self, context: &ManagedContext) -> bool {
        if self.persistence_status != TransactionPersistenceStatus::NotSaved {
            return false;
        }
        self.persistence_status = TransactionPersistenceStatus::Saving;
        // add the transaction to DB
        context.perform_block(|context| {
            match TransactionEntity::count_transactions_for_hash(&self.tx_hash(), context) {
                Ok(0) =>
                    match TransactionEntity::save_transaction_for(self.chain().r#type(), self, context) {
                        Ok(..) => {
                            self.persistence_status = TransactionPersistenceStatus::Saved;
                        },
                        Err(err) => {
                            println!("Can't store transaction");
                            self.persistence_status = TransactionPersistenceStatus::NotSaved;
                        },
                    },
                _ => {
                    println!("Can't store transaction");
                    self.persistence_status = TransactionPersistenceStatus::NotSaved;
                }
            }
        });
        true
    }
}
impl<'a> TryRead<'a, Endian> for Transaction {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let version = bytes.read_with::<u16>(offset, endian)?;
        let tx_type_uint = bytes.read_with::<u16>(offset, endian)?;
        let tx_type = TransactionType::from(tx_type_uint);
        let count_var = bytes.read_with::<VarInt>(offset, endian)?;
        let count = count_var.0;
        // at least one input is required
        if count == 0 && tx_type.requires_inputs() {
            return Err(byte::Error::Incomplete);
        }
        let mut inputs: Vec<TransactionInput> = Vec::new();
        for _i in 0..count {
            inputs.push(bytes.read_with::<TransactionInput>(offset, endian)?);
        }
        let mut outputs: Vec<TransactionOutput> = Vec::new();
        let count_var = bytes.read_with::<VarInt>(offset, endian)?;
        let count = count_var.0;
        for _i in 0..count {
            outputs.push(bytes.read_with::<TransactionOutput>(offset, endian)?);
        }
        let lock_time = bytes.read_with::<u32>(offset, endian)?;
        let mut tx = Self {
            inputs,
            outputs,
            version,
            tx_type,
            lock_time,
            payload_offset: *offset,
            block_height: TX_UNCONFIRMED as u32,
            ..Default::default()
        };
        if tx_type != TransactionType::Classic {
            return Ok((tx, *offset));
        } else {
            // only classic transactions are shapeshifted
            tx.tx_hash = UInt256::sha256d(&tx.to_data());
            if let Some(outbound_shapeshift_address) = tx.shapeshift_outbound_address() {
                if let Ok(mut entity) = ShapeshiftEntity::having_withdrawal_address(&outbound_shapeshift_address, tx.chain().chain_context()) {
                    if entity.shapeshift_status == ShapeshiftAddressStatus::Unused.into() {
                        entity.shapeshift_status = ShapeshiftAddressStatus::NoDeposits.into();
                        // save later
                    }
                    tx.associated_shapeshift = Some(entity);
                } else if let Some(possibleOutboundShapeshiftAddress) = tx.shapeshift_outbound_address_force_script() {
                    if let Ok(mut entity) = ShapeshiftEntity::having_withdrawal_address(&possibleOutboundShapeshiftAddress, tx.chain().chain_context()) {
                        if entity.shapeshift_status = ShapeshiftAddressStatus::Unused.into() {
                            entity.shapeshift_status = ShapeshiftAddressStatus::NoDeposits.into();
                            // save later
                        }
                        tx.associated_shapeshift = Some(entity);
                    }
                }
                if tx.associated_shapeshift.is_none() && !tx.outputs().is_empty() {
                    let mut all_addresses = Vec::<String>::new();
                    match AddressEntity::all(tx.chain().chain_context()) {
                        Ok(entities) => {
                            all_addresses = entities.iter().map(|e| e.address).collect();
                        },
                        Err(err) => panic!("Can't read all address entities")
                    }
                    if let Some(main_output_address) = tx.outputs().iter().find_map(|output| {
                        if let Some(addr) = &output.address {
                            if all_addresses.contains(addr) {
                                return Some(addr);
                            }
                        }
                        None
                    }) {
                        if let Ok(entity) = ShapeshiftEntity::register_shapeshift_with_addess(main_output_address, &outbound_shapeshift_address, ShapeshiftAddressStatus::NoDeposits, tx.chain().chain_context()) {
                            tx.associated_shapeshift = Some(entity);
                        }
                    }
                }
            } else {
                return Ok((tx, *offset));
            }
        }
        Ok((tx, *offset))
    }
}
