use chrono::NaiveDateTime;
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryResult, QuerySource, Table};
use diesel::query_builder::QueryFragment;
use diesel::sqlite::Sqlite;
use futures::StreamExt;
use crate::chain::block::IBlock;
use crate::chain::chain::Chain;
use crate::chain::chain_lock::ChainLock;
use crate::chain::checkpoint::Checkpoint;
use crate::chain::common::ChainType;
use crate::consensus::Encodable;
use crate::crypto::UInt256;
use crate::schema::chains;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::account::friend_request::FriendRequestEntity;
use crate::storage::models::account::identity::IdentityEntity;
use crate::storage::models::account::user::UserEntity;
use crate::storage::models::chain::block::BlockEntity;
use crate::storage::models::chain::chain_lock::ChainLockEntity;
use crate::storage::models::chain::checkpoint::CheckpointEntity;
use crate::storage::models::common::address::AddressEntity;
use crate::storage::models::common::derivation_path::DerivationPathEntity;
use crate::storage::models::entity::Entity;
use crate::storage::models::masternode::{LocalMasternodeEntity, MasternodeEntity, MasternodeListEntity, QuorumEntity};
use crate::storage::models::masternode::llmq_snapshot::LLMQSnapshotEntity;
use crate::storage::models::tx::transaction::TransactionEntity;

#[derive(Identifiable, Queryable, PartialEq, Eq, Debug)]
#[diesel(table_name = chains)]
pub struct ChainEntity {
    pub id: i32,
    pub chain_type: i16,
    pub version: Option<i16>,
    pub identifier: Option<String>,

    pub total_governance_objects_count: i32,
    pub base_block_hash: Option<UInt256>,

    pub sync_block_chain_work: Option<UInt256>,
    pub sync_block_hash: Option<UInt256>,
    pub sync_block_height: Option<i32>,
    pub sync_block_timestamp: Option<NaiveDateTime>,
    pub sync_locators: Option<Vec<u8>>, //Vec<UInt256>

    pub account_ids: Vec<i32>, // AccountEntity
    pub block_ids: Vec<i32>, // MerkleBlockEntity
    pub checkpoint_ids: Vec<i32>, // CheckpointEntity
    pub contact_ids: Vec<i32>, // ContactEntity
    pub contract_ids: Vec<i32>, // ContractEntity
    pub derivation_path_ids: Vec<i32>, // DerivationPathEntity
    pub governance_object_hash_ids: Vec<i32>, // GovernanceObjectHashEntity
    pub governance_vote_hash_ids: Vec<i32>, // GovernanceVoteHashEntity
    pub identity_ids: Vec<i32>, // IdentityEntity
    pub last_chain_lock_id: Option<i32>, // ChainLockEntity
    pub peer_ids: Vec<i32>, // PeerEntity
    pub quorum_ids: Vec<i32>, // PeerEntity
    pub masternode_ids: Vec<i32>, // PeerEntity
    pub spork_ids: Vec<i32>, // PeerEntity
    pub transaction_hash_ids: Vec<i32>, // TransactionHashEntity
}

#[derive(Insertable, PartialEq, Eq, Debug)]
#[diesel(table_name = chains)]
pub struct NewChainEntity {
    pub chain_type: i16,
    pub version: Option<i16>,
    pub identifier: Option<&'static str>,

    pub total_governance_objects_count: i32,
    pub last_chain_lock_id: Option<i32>,
    pub base_block_hash: Option<UInt256>,

    pub sync_block_chain_work: UInt256,
    pub sync_block_hash: UInt256,
    pub sync_block_height: i32,
    pub sync_block_timestamp: NaiveDateTime,
    pub sync_locators: Option<Vec<u8>>, //Vec<UInt256>
}

pub struct ChainAggregate {
    pub chain: &'static ChainEntity,
    pub checkpoints: &'static Vec<CheckpointEntity>,
}

impl Entity for ChainEntity {
    type ID = chains::id;
    // type ChainId = chains::id;

    fn id(&self) -> i32 {
        self.id
    }

    fn target<T>() -> T where T: Table + QuerySource, T::FromClause: QueryFragment<Sqlite> {
        todo!()
        //         chains::dsl::chains
    }
}

impl ChainEntity {

    fn update_last_chain_lock_if_need(&self, chain_lock_id: i32, chain_lock: &ChainLock, context: &ManagedContext) -> QueryResult<usize> {
        if chain_lock.signature_verified {
            let updater = || self.update_with(chains::last_chain_lock_id.eq(Some(chain_lock_id)), context);
            if let Some(current_id) = self.last_chain_lock_id {
                ChainLockEntity::get_by_id(current_id, context)
                    .and_then(|current_lock| current_lock.get_block(context)
                        .and_then(|current_lock_block| {
                            if current_lock_block.height < chain_lock.height as i32 {
                                updater()
                            } else {
                                Ok(0)
                            }
                        }))
            } else {
                updater()
            }
        } else {
            Ok(0)
        }
    }

    fn get_last_chain_lock(&self, context: &ManagedContext) -> QueryResult<ChainLockEntity> {
        if let Some(last_id) = self.last_chain_lock_id {
            ChainLockEntity::get_by_id(last_id, context)
        } else {
            Err(diesel::result::Error::NotFound)
        }
    }

    fn unique_predicate<P>(r#type: ChainType) -> P {
        let predicate = chains::chain_type.eq(r#type.into())
            .and(chains::chain_type.ne(ChainType::DevNet.into())
                .or(chains::identifier.eq(r#type.devnet_identifier())));
    }

    pub fn aggregate_for_type(r#type: ChainType, checkpoints: &Vec<Checkpoint>, context: &ManagedContext) -> QueryResult<ChainAggregate> {
        // predicate = [NSPredicate predicateWithFormat:@"type = %d && ((type != %d) || devnetIdentifier = %@)", type, DSChainType_DevNet, devnetIdentifier]
        let devnet_identifier = r#type.devnet_identifier();
        let predicate = Self::unique_predicate(r#type);
        let entities: Result<Vec<ChainEntity>, diesel::result::Error> = ChainEntity::read(predicate, context);
        match entities {
            Ok(objects) if !objects.is_empty() => {
                assert_eq!(objects.len(), 1, "There should only ever be 1 chain for either mainnet, testnet, or a devnet Identifier");
                if objects.len() > 1 {
                    // This is very bad, just remove all above 1
                    objects.iter().skip(1).for_each(|object| {
                        Self::delete_by_id(object.id, context);
                        println!("Removing extra chain entity of type {:?}", r#type);
                    });
                }
                // todo: ensure our checkpoints are match with entities
                Ok(ChainAggregate {
                    chain: objects.first().unwrap(),
                    checkpoints: &CheckpointEntity::checkpoints_by_chain_id(objects.first().unwrap().id, context)
                        .unwrap_or(vec![]) })
            },
            Ok(..) => {
                match Self::create_and_get(&NewChainEntity {
                    chain_type: r#type.into(),
                    version: r#type.devnet_version(),
                    identifier: devnet_identifier,
                    ..Default::default()
                }, context) {
                    Ok(entity) => Ok(ChainAggregate {
                        chain: &entity,
                        // TODO: convert to checkpoint entities
                        checkpoints: &CheckpointEntity::create_many(checkpoints, context)
                            .unwrap_or(vec![])
                    }),
                    Err(err) => Err(err)
                }
            },
            Err(err) => Err(err)
        }
    }

    pub fn save_block_locators(r#type: ChainType, last_block: &dyn IBlock, sync_locators: &Vec<UInt256>, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = Self::unique_predicate(r#type);
        let mut sync_locators_bytes = Vec::<u8>::new();
        sync_locators.iter()
            .for_each(|locator| {
                locator.enc(&mut sync_locators_bytes);
            });
        let values = (
            chains::sync_block_hash.eq(&last_block.block_hash()),
            chains::sync_block_height.eq(&last_block.height()),
            chains::sync_block_timestamp.eq(&last_block.timestamp()),
            chains::sync_block_chain_work.eq(&last_block.chain_work()),
            chains::sync_locators.eq(sync_locators_bytes)
        );
        Self::update(predicate, &values, context)
    }

    pub fn update_block_hash_and_governance(r#type: ChainType, base_block_hash: &UInt256, total_governance_object_count: i32, context: &ManagedContext) -> QueryResult<usize> {
        let predicate = Self::unique_predicate(r#type);
        let values = (
            chains::total_governance_objects_count.eq(total_governance_object_count),
            chains::base_block_hash.eq(base_block_hash)
        );
        Self::update(predicate, values, context)
    }

    pub fn get_chain(r#type: ChainType, context: &ManagedContext) -> QueryResult<Self> {
        let predicate = Self::unique_predicate(r#type);
        Self::any(predicate, context)
    }

    pub fn wipe_masternode_data(r#type: ChainType, context: &ManagedContext) -> QueryResult<usize> {
        Self::get_chain(r#type, context)
            .map(|entity| {
                let chain_id = entity.id;
                LocalMasternodeEntity::delete_by_chain_id(chain_id, context).expect("Can't delete local masternode entities for chain");
                MasternodeEntity::delete_by_chain_id(chain_id, context).expect("Can't delete masternode entities for chain");
                QuorumEntity::delete_by_chain_id(chain_id, context).expect("Can't delete quorum entities for chain");
                MasternodeListEntity::delete_by_chain_id(chain_id, context).expect("Can't delete masternode list entities for chain");
                LLMQSnapshotEntity::delete_by_chain_id(chain_id, context).expect("Can't delete llmq snapshot entities for chain");
                1
            })
    }

    pub fn wipe_blockchain_data(r#type: ChainType, context: &ManagedContext) -> QueryResult<usize> {
        Self::get_chain(r#type, context)
            .and_then(|entity| {
                let chain_id = entity.id;
                BlockEntity::delete_by_chain_id(chain_id, context).expect("Can't delete block entities for chain");
                AddressEntity::delete_by_chain_id(chain_id, context).expect("Can't delete address entities for chain");
                TransactionEntity::delete_by_chain_id(chain_id, context).expect("Can't delete transaction entities for chain");
                DerivationPathEntity::delete_by_chain_id(chain_id, context).expect("Can't delete derivation path entities for chain");
                FriendRequestEntity::delete_by_chain_id(chain_id, context).expect("Can't delete friend request entities for chain");
                IdentityEntity::delete_by_chain_id(chain_id, context).expect("Can't delete identity entities for chain");
                // this must move after wipeBlockchainInfo where blockchain identities are removed
                UserEntity::delete_by_chain_id(chain_id, context).expect("Can't delete user entities for chain");
                Self::delete_by_id(chain_id, context)
            })
    }

    pub fn wipe_blockchain_non_terminal_data(r#type: ChainType, context: &ManagedContext) -> QueryResult<usize> {
        Self::get_chain(r#type, context)
            .and_then(|entity| {
                let chain_id = entity.id;
                LocalMasternodeEntity::delete_by_chain_id(chain_id, context).expect("Can't delete local masternode entities for chain");
                MasternodeEntity::delete_by_chain_id(chain_id, context).expect("Can't delete masternode entities for chain");
                QuorumEntity::delete_by_chain_id(chain_id, context).expect("Can't delete llmq entities for chain");
                MasternodeListEntity::delete_by_chain_id(chain_id, context).expect("Can't delete masternode list entities for chain");
                LLMQSnapshotEntity::delete_by_chain_id(chain_id, context).expect("Can't delete llmq snapshot entities for chain");
                AddressEntity::delete_by_chain_id(chain_id, context).expect("Can't delete address entities for chain");
                TransactionEntity::delete_by_chain_id(chain_id, context).expect("Can't delete transaction entities for chain");
                DerivationPathEntity::delete_by_chain_id(chain_id, context).expect("Can't delete derivation path entities for chain");
                FriendRequestEntity::delete_by_chain_id(chain_id, context).expect("Can't delete friend request entities for chain");
                IdentityEntity::delete_by_chain_id(chain_id, context).expect("Can't delete identity entities for chain");
                // this must move after wipeBlockchainInfo where blockchain identities are removed
                UserEntity::delete_by_chain_id(chain_id, context).expect("Can't delete user entities for chain");
                Self::delete_by_id(chain_id, context)
            })
    }

    pub fn wipe_wallet_data(r#type: ChainType, context: &ManagedContext) -> QueryResult<usize> {
        Self::get_chain(r#type, context)
            .and_then(|entity| {
                let chain_id = entity.id;
                BlockEntity::delete_by_chain_id(chain_id, context).expect("Can't delete block entities for chain");
                AddressEntity::delete_by_chain_id(chain_id, context).expect("Can't delete address entities for chain");
                TransactionEntity::delete_by_chain_id(chain_id, context).expect("Can't delete transaction entities for chain");
                DerivationPathEntity::delete_by_chain_id(chain_id, context).expect("Can't delete derivation path entities for chain");
                FriendRequestEntity::delete_by_chain_id(chain_id, context).expect("Can't delete friend request entities for chain");
                IdentityEntity::delete_by_chain_id(chain_id, context).expect("Can't delete identity entities for chain");
                // this must move after wipeBlockchainInfo where blockchain identities are removed
                UserEntity::delete_by_chain_id(chain_id, context).expect("Can't delete user entities for chain");
                Self::delete_by_id(chain_id, context)
            })
    }
    pub fn chain_by_id(chain_id: i32, context: &ManagedContext) -> QueryResult<Chain> {
        todo!("impl Chain from ChainEntity")
    }

    pub fn chain(&self) -> QueryResult<Chain> {
        todo!("impl Chain from ChainEntity")
    }
}

// impl ChainEntity {
//
//     pub fn update_peers_with_addresses(&self, addresses: &Vec<i32>, context: &ManagedContext) -> QueryResult<usize> {
//         let predicate = peers::chain_id.eq(self.id)
//             .and(peers::address.eq_any(addresses));
//         PeerEntity::update(predicate, context)
        // ChainEntity::get_chain(chain_type, context)
        //     .and_then(|chain_entity|
        //
        //         Self::delete_by(
        //             peers::chain_id.eq(chain_entity.id)
        //                 .and(peers::address.ne_all(keep_addresses)),
        //             context))
    //
    // }
//
// }
