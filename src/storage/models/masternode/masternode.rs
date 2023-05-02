use std::collections::BTreeMap;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, QueryResult, QuerySource, RunQueryDsl, Table};
use diesel::expression::AsExpression;
use diesel::query_builder::QueryFragment;
use diesel::serialize::{IsNull, Output};
use diesel::sql_types::Binary;
use diesel::sqlite::Sqlite;

use crate::chain::common;
use crate::chain::common::BlockData;
use crate::crypto::{Boolean, UInt128, UInt160, UInt256};
use crate::chain::masternode::{MasternodeEntry, OperatorPublicKey};
use crate::schema::masternodes;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::masternode::LocalMasternodeEntity;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, FromSqlRow, AsExpression)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct OperatorPublicKeyAtBlockHash {
    pub block_hash: UInt256,
    pub key: OperatorPublicKey
}

impl<'a> TryRead<'a, Endian> for OperatorPublicKeyAtBlockHash {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let block_hash = bytes.read_with::<UInt256>(offset, endian).unwrap();
        let key = bytes.read_with::<OperatorPublicKey>(offset, endian).unwrap();
        Ok((Self { block_hash, key }, *offset))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, FromSqlRow, AsExpression)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct MasternodeEntryHashAtBlockHash {
    pub block_hash: UInt256,
    pub entry_hash: UInt256
}
impl<'a> TryRead<'a, Endian> for MasternodeEntryHashAtBlockHash {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let block_hash = bytes.read_with::<UInt256>(offset, endian).unwrap();
        let entry_hash = bytes.read_with::<UInt256>(offset, endian).unwrap();
        Ok((Self { block_hash, entry_hash }, *offset))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, FromSqlRow, AsExpression)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct ValidityAtBlockHash {
    pub block_hash: UInt256,
    pub validity: Boolean,
}
impl<'a> TryRead<'a, Endian> for ValidityAtBlockHash {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let block_hash = bytes.read_with::<UInt256>(offset, endian).unwrap();
        let validity = bytes.read_with::<Boolean>(offset, endian).unwrap();
        Ok((Self { block_hash, validity }, *offset))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, FromSqlRow, AsExpression)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct PrevValidity {
    pub data: Vec<ValidityAtBlockHash>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, FromSqlRow, AsExpression)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct PrevOperatorBLSPublicKeys {
    pub data: Vec<OperatorPublicKeyAtBlockHash>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, FromSqlRow, AsExpression)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct PrevMasternodeEntryHashes {
    pub data: Vec<MasternodeEntryHashAtBlockHash>,
}

impl diesel::serialize::ToSql<Binary, Sqlite> for PrevValidity {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Sqlite>) -> diesel::serialize::Result {
        out.set_value(self);
        Ok(IsNull::No)
    }
}


/// queries
/// "chain == %@"
/// "(((address >> %@) & 255) == %@)"
/// "ANY masternodeLists.block.height == %@"
/// "masternodeLists.@count == 0"
/// "utxoHash == %@ && utxoIndex == %@" ????
/// "providerRegistrationTransactionHash == %@"
#[derive(Identifiable, Queryable, Associations, PartialEq, Eq, Debug)]
#[diesel(belongs_to(LocalMasternodeEntity, foreign_key = local_masternode_id))]
#[diesel(belongs_to(ChainEntity, foreign_key = chain_id))]
#[diesel(table_name = masternodes)]
pub struct MasternodeEntity {
    pub id: i32,
    pub address: i64,
    pub port: i16,
    pub core_last_connection_date: Option<NaiveDateTime>,
    pub core_protocol: i64,
    pub core_version: Option<String>,
    pub is_valid: bool,
    pub platform_ping: i64,
    pub platform_ping_date: Option<NaiveDateTime>,
    pub platform_version: Option<String>,
    pub known_confirmed_at_height: i32,
    pub update_height: i32,
    pub prev_operator_bls_public_keys: PrevOperatorBLSPublicKeys,
    pub prev_masternode_entry_hashes: PrevMasternodeEntryHashes,
    pub prev_validity: PrevValidity,
    pub confirmed_hash: UInt256,
    pub ipv6_address: UInt128,
    pub key_id_voting: UInt160,
    pub operator_bls_public_key: OperatorPublicKey,
    pub provider_registration_transaction_hash: UInt256,
    pub masternode_entry_hash: UInt256,

    pub chain_id: i32,
    pub local_masternode_id: Option<i32>,
    // pub address_ids: Vec<i32>,
    // pub governance_vote_ids: Vec<i32>,
    // pub masternode_list_ids: Vec<i32>,
}

#[derive(Insertable, Associations, PartialEq, Eq, Debug)]
#[diesel(belongs_to(LocalMasternodeEntity, foreign_key = local_masternode_id))]
#[diesel(belongs_to(ChainEntity, foreign_key = chain_id))]
#[diesel(table_name = masternodes)]
pub struct NewMasternodeEntity {
    pub address: i64,
    pub port: i16,
    pub core_last_connection_date: Option<NaiveDateTime>,
    pub core_protocol: i64,
    pub core_version: Option<&'static str>,
    pub is_valid: bool,
    pub platform_ping: i64,
    pub platform_ping_date: Option<NaiveDateTime>,
    pub platform_version: Option<&'static str>,
    pub known_confirmed_at_height: i32,
    pub update_height: i32,
    pub prev_operator_bls_public_keys: PrevOperatorBLSPublicKeys,
    pub prev_masternode_entry_hashes: PrevMasternodeEntryHashes,
    pub prev_validity: PrevValidity,
    pub confirmed_hash: UInt256,
    pub ipv6_address: UInt128,
    pub key_id_voting: UInt160,
    pub operator_bls_public_key: OperatorPublicKey,
    pub provider_registration_transaction_hash: UInt256,
    pub masternode_entry_hash: UInt256,

    pub chain_id: i32,
    pub local_masternode_id: Option<i32>,
    // pub address_ids: Vec<i32>,
    // pub governance_vote_ids: Vec<i32>,
    // pub masternode_list_ids: Vec<i32>,
}


//"block.chain == %@ && masternodes.@count == 0"
//NSArray *matchingMasternodeEntities = [DSSimplifiedMasternodeEntryEntity objectsInContext:self.managedObjectContext matching:@"utxoHash == %@ && utxoIndex == %@", masternodeHashData, @(governanceVote.masternodeUTXO.n)];
//DSSimplifiedMasternodeEntryEntity *simplifiedMasternodeEntryEntity = [DSSimplifiedMasternodeEntryEntity anyObjectInContext:self.managedObjectContext matching:@"providerRegistrationTransactionHash == %@", uint256_data(localMasternode.providerRegistrationTransaction.txHash)];

impl Entity for MasternodeEntity {
    type ID = masternodes::id;
    // type ChainId = masternodes::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         masternodes::dsl::masternodes
    }
}

impl MasternodeEntity {
    pub fn create_masternode(
        chain_id: i32,
        address: i64,
        port: i16,
        core_last_connection_date: Option<NaiveDateTime>,
        core_protocol: i64,
        core_version: Option<&str>,
        is_valid: bool,
        platform_ping: i64,
        platform_ping_date: Option<NaiveDateTime>,
        platform_version: Option<&str>,
        known_confirmed_at_height: i32,
        update_height: i32,
        local_masternode_id: Option<i32>,
        prev_operator_bls_public_keys: Vec<OperatorPublicKeyAtBlockHash>,
        prev_masternode_entry_hashes: Vec<MasternodeEntryHashAtBlockHash>,
        prev_validity: Vec<ValidityAtBlockHash>,
        confirmed_hash: UInt256,
        ipv6_address: UInt128,
        key_id_voting: UInt160,
        operator_bls_public_key: OperatorPublicKey,
        provider_registration_transaction_hash: UInt256,
        masternode_entry_hash: UInt256,
        context: &ManagedContext
    ) -> QueryResult<usize> {
        let records = NewMasternodeEntity {
            chain_id,
            address,
            port,
            core_last_connection_date,
            core_protocol,
            core_version,
            is_valid,
            platform_ping,
            platform_ping_date,
            platform_version,
            known_confirmed_at_height,
            update_height,
            local_masternode_id,
            prev_operator_bls_public_keys,
            prev_masternode_entry_hashes,
            prev_validity,
            confirmed_hash,
            ipv6_address,
            key_id_voting,
            operator_bls_public_key,
            provider_registration_transaction_hash,
            masternode_entry_hash,
        };
        Self::create(&records, context)
    }


    /// "(providerRegistrationTransactionHash == %@) && (chain == %@)"
    pub fn read_masternode<'a, Predicate>(predicate: Predicate, context: &ManagedContext) -> QueryResult<MasternodeEntity>
        where Predicate:
        diesel::Expression<SqlType = diesel::sql_types::Bool> +
        diesel::expression::NonAggregate +
        diesel::expression::AppearsOnTable<masternodes::dsl::masternodes> +
        diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> +
        diesel::query_builder::QueryId {
        Self::any(predicate, context)
    }

    /// "(providerRegistrationTransactionHash == %@) && (chain == %@)"
    pub fn masternode_with_pro_reg_tx_hash(chain_id: i32, pro_reg_tx_hash: UInt256, context: &ManagedContext) -> QueryResult<MasternodeEntity> {
        let predicate = masternodes::chain_id.eq(chain_id)
            .and(masternodes::provider_registration_transaction_hash.eq(pro_reg_tx_hash));
        Self::read_masternode(predicate, context)
    }

    pub fn get_by_pro_reg_tx_hash(pro_reg_tx_hash: &UInt256, context: &ManagedContext) -> QueryResult<MasternodeEntity> {
        let predicate = masternodes::provider_registration_transaction_hash.eq(pro_reg_tx_hash);
        Self::any(predicate, context)
    }


    /// "(simplifiedMasternodeEntryHash == %@) && (chain == %@)"
    pub fn masternode_with_entry_hash<'a>(chain_id: i32, entry_hash: UInt256, context: &ManagedContext) -> QueryResult<MasternodeEntity> {
        let predicate = masternodes::chain_id.eq(chain_id)
            .and(masternodes::masternode_entry_hash.eq(entry_hash));
        Self::read_masternode(predicate, context)
    }


    pub fn delete_masternodes(chain_id: i32, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = masternodes::chain_id.eq(chain_id);
        let source = Self::target().filter(predicate);
        Self::delete(source, context)
    }

    /// "(chain == %@) && (providerRegistrationTransactionHash IN %@)"
    pub fn delete_having_provider_transaction_hashes(chain_id: i32, hashes: Vec<UInt256>, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = masternodes::chain_id.eq(chain_id)
            .and(masternodes::provider_registration_transaction_hash.eq_any(hashes));
        let source = Self::target().filter(predicate);
        Self::delete(source, context)
    }

    /// "masternodeLists.@count == 0"
    pub fn delete_masternodes_with_empty_lists(chain_id: i32, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = masternodes::chain_id.eq(chain_id);
        let source = Self::target().filter(predicate);
        Self::delete(source, context)
    }

    pub fn save_plaform_ping_info(chain_id: i32, pro_reg_tx_hash: UInt256, platform_ping: i64, platform_ping_date: NaiveDateTime, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = masternodes::chain_id.eq(chain_id)
            .and(masternodes::provider_registration_transaction_hash.eq(pro_reg_tx_hash));
        let source = Self::target().filter(predicate);
        let values = (masternodes::platform_ping.eq(platform_ping),
                      masternodes::platform_ping_date.eq(Some(platform_ping_date)));

        diesel::update(source)
            .set(values)
            .execute(context.pool())
    }

    pub fn update_plaform_ping_info(pro_reg_tx_hash: &UInt256, platform_ping: u64, platform_ping_date: u64, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = masternodes::provider_registration_transaction_hash.eq(pro_reg_tx_hash);
        let source = Self::target().filter(predicate);
        let values = (masternodes::platform_ping.eq(platform_ping),
                      masternodes::platform_ping_date.eq(NaiveDateTime::from_timestamp_opt(platform_ping_date as i64, 0)));
        diesel::update(source)
            .set(values)
            .execute(context.pool())
    }
    pub fn simplified_masternode_entry_with_block_height_lookup<BHL>(&self, block_height_lookup: BHL) -> MasternodeEntry
        where BHL: Fn(UInt256) -> u32 {
        // chain ???
        // confirmed_hash_hashed_with_provider_registration_transaction_hash ???
        // block data ???
        // let block_height = block_height_lookup(self.)

        let previous_operator_public_keys = self.prev_operator_bls_public_keys.iter().fold(BTreeMap::new(), |mut acc, key| {
            acc.insert(BlockData { height: block_height_lookup(key.block_hash), hash: key.block_hash }, key.key);
            acc
        });
        let previous_entry_hashes = self.prev_masternode_entry_hashes.iter().fold(BTreeMap::new(), |mut acc, key| {
            acc.insert(BlockData { height: block_height_lookup(key.block_hash), hash: key.block_hash }, key.entry_hash);
            acc
        });
        let previous_validity = self.prev_validity.iter().fold(BTreeMap::new(), |mut acc, key| {
            acc.insert(BlockData { height: block_height_lookup(key.block_hash), hash: key.block_hash }, key.validity.0);
            acc
        });

        MasternodeEntry {
            provider_registration_transaction_hash: self.provider_registration_transaction_hash,
            confirmed_hash: self.confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash: None,
            socket_address: common::SocketAddress {
                ip_address: self.ipv6_address,
                port: self.port as u16
            },
            operator_public_key: self.operator_bls_public_key,
            previous_operator_public_keys,
            previous_entry_hashes,
            previous_validity,
            known_confirmed_at_height: Some(self.known_confirmed_at_height as u32),
            update_height: self.update_height as u32,
            key_id_voting: self.key_id_voting,
            is_valid: self.is_valid,
            entry_hash: self.masternode_entry_hash,
            platform_ping: self.platform_ping as u64,
            platform_ping_date: self.platform_ping_date.map_or(0, |date| date.timestamp() as u64)
        }
    }

}
