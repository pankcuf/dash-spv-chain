use std::collections::BTreeMap;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, QueryResult, QuerySource, RunQueryDsl, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use crate::chain::common::LLMQType;
use crate::crypto::UInt256;
use crate::chain::masternode;
use crate::chain::masternode::{LLMQEntry, MasternodeEntry, MasternodeList};
use crate::schema;
use crate::storage::models::masternode::QuorumEntity;
use crate::schema::masternode_lists;
use crate::schema::masternode_list_masternodes;
use crate::schema::masternode_list_quorums;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::entity::Entity;
// "block.height < %@ && block.blockHash IN %@ && (block.usedByQuorums.@count == 0)";

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = masternode_lists)]
pub struct MasternodeListEntity {
    pub id: i32,
    pub masternodes_merkle_root: UInt256,
    pub quorums_merkle_root: Option<UInt256>,

    pub block_id: i32,
    pub chain_id: i32,
    // pub masternode_ids: Vec<i32>,
    // pub quorum_ids: Vec<i32>,
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = masternode_lists)]
pub struct NewMasternodeListEntity {
    pub masternodes_merkle_root: UInt256,
    pub quorums_merkle_root: Option<UInt256>,

    pub block_id: i32,
    pub chain_id: i32,
    // pub masternode_ids: Vec<i32>,
    // pub quorum_ids: Vec<i32>,
}

impl Entity for MasternodeListEntity {
    type ID = masternode_lists::id;
    // type ChainId = masternode_lists::chain_id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //        masternode_lists::dsl::masternode_lists
    }
}


impl MasternodeListEntity {
    pub fn create_masternode_list(block_id: i32,
                                  chain_id: i32,
                                  masternodes_merkle_root: UInt256,
                                  quorums_merkle_root: Option<UInt256>,
                                  context: &ManagedContext

    ) -> QueryResult<usize> {
        let target = masternode_lists::dsl::masternode_lists;
        let records = NewMasternodeListEntity { block_id, chain_id, masternodes_merkle_root, quorums_merkle_root };
        Self::create(&records, context)
    }

    pub fn delete_masternode_list(chain_id: i32, block_id: i32, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = masternode_lists::chain_id.eq(chain_id)
            .and(masternode_lists::block_id.eq(block_id));
        let source = Self::target().filter(predicate);
        Self::delete(source, context)
    }

    pub fn delete_masternode_lists(chain_id: i32, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = masternode_lists::chain_id.eq(chain_id);
        let source = Self::target().filter(predicate);
        Self::delete(source, context)
    }

    /// "block.chain == %@ && masternodes.@count == 0"
// pub fn delete_empty_masternode_lists(chain_id: i32) -> QueryResult<usize> {
//     let predicate = masternode_lists::chain_id.eq(chain_id);
//     // let hardware = hardware::table
//     //     .left_join(units::table.on(hardware::unit_id.eq(units::id.nullable())))
//
//     //schema::masternode_list_masternodes::table::left_join()
// }

    pub fn update_masternode_list(block_id: i32, chain_id: i32, masternodes_root: UInt256, quorums_root: UInt256, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = masternode_lists::chain_id.eq(chain_id)
            .and(masternode_lists::block_id.eq(block_id));
        let source = Self::target().filter(predicate);
        let values = (masternode_lists::masternodes_merkle_root.eq(masternodes_root),
                      masternode_lists::quorums_merkle_root.eq(quorums_root));
        diesel::update(source)
            .set(values)
            .execute(context.pool())
    }

    pub fn masternode_list_for_block(chain_id: i32, block_id: i32, context: &ManagedContext) -> QueryResult<MasternodeListEntity> {
        let predicate = masternode_lists::chain_id.eq(chain_id)
            .and(masternode_lists::block_id.eq(block_id));
        Self::any(predicate, context)
    }

    pub fn masternode_lists_for_chain(chain_id: i32, context: &ManagedContext) -> QueryResult<Vec<MasternodeListEntity>> {
        let predicate = masternode_lists::chain_id.eq(chain_id);
        Self::read(predicate, context)
    }

    /// "block.height < %@ && block.blockHash IN %@ && (block.usedByQuorums.@count == 0)"
    pub fn masternode_lists_in(chain_id: i32, block_ids: Vec<i32>, context: &ManagedContext) -> QueryResult<Vec<MasternodeListEntity>> {
        let predicate = masternode_lists::chain_id.eq(chain_id)
            .and(masternode_lists::block_id.eq_any(block_ids));
        // TODO: make it normal
        Self::read(predicate, context)
    }
    //+ (void)deleteAllOnChainEntity:(DSChainEntity *)chainEntity;

    pub fn masternode_list_with_simplified_masternode_entry_pool_and_lookup<BHL>(
        &self,
        masternodes: BTreeMap<UInt256, MasternodeEntry>,
        quorums: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>>,
        context: &ManagedContext,
        block_height_lookup: BHL
    ) -> masternode::MasternodeList
        where BHL: Fn(UInt256) -> u32 + Copy
    {
        let mut masternode_entries: BTreeMap<UInt256, MasternodeEntry> = BTreeMap::new();
        let mut quorum_entries: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>> = BTreeMap::new();

        if let Ok(ids) = masternode_list_masternodes::dsl::masternode_list_masternodes
            .select(masternode_list_masternodes::masternode_id)
            .filter(masternode_list_masternodes::dsl::masternode_list_id.eq(self.id))
            .get_results::<i32>(context) {
            ids.iter().for_each(|&i| {
                if let Ok(result) = Self::read(schema::masternodes::dsl::id.eq(i), context) {
                    result.iter().for_each(|entity| {
                        let hash = entity.provider_registration_transaction_hash;
                        if let Some(node) = masternodes.get(&hash) {
                            masternode_entries.insert(hash, node.clone());
                        } else {
                            masternode_entries.insert(hash, entity.simplified_masternode_entry_with_block_height_lookup(block_height_lookup));
                        }
                    });
                }
            });
        }
        if let Ok(ids) = masternode_list_quorums::dsl::masternode_list_quorums
            .select(masternode_list_quorums::quorum_id)
            .filter(masternode_list_quorums::dsl::masternode_list_id.eq(self.id))
            .get_results::<i32>(&context.connection()) {
            ids.iter().for_each(|&i| {
                if let Ok(result) =  schema::quorums::dsl::quorums
                    .select(schema::quorums::dsl::quorums::all_columns())
                    .filter(schema::quorums::dsl::id.eq(i))
                    .get_results::<QuorumEntity>(context.pool()) {
                    result.iter().for_each(|entity| {
                        let llmq_type = LLMQType::from(entity.quorum_type as u8);
                        let llmq_hash = entity.quorum_hash;
                        quorum_entries.entry(llmq_type).or_insert(BTreeMap::new()).insert(llmq_hash.clone(), if let Some(quorums_of_type) = quorums.get(&llmq_type) {
                            if let Some(entry) = quorums_of_type.get(&llmq_hash) {
                                Some(entry.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }.unwrap_or(entity.to_model()));
                    });
                }
            });
        }



        MasternodeList {
            block_hash: Default::default(),
            known_height: u32::MAX,
            masternode_merkle_root: Some(self.masternodes_merkle_root),
            llmq_merkle_root: self.quorums_merkle_root,
            masternodes: masternode_entries,
            quorums: quorum_entries
        }

        //[DSMasternodeList masternodeListWithSimplifiedMasternodeEntries:
        // masternodeEntriesArray quorumEntries:quorumEntriesArray
        // atBlockHash:self.block.blockHash.UInt256
        // atBlockHeight:self.block.height
        // withMasternodeMerkleRootHash:self.masternodeListMerkleRoot.UInt256
        // withQuorumMerkleRootHash:self.quorumListMerkleRoot.UInt256
        // onChain:self.block.chain.chain];

    }

}





