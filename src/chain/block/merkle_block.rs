use std::collections::HashMap;
use byte::{BytesExt, TryRead};
use byte::ctx::Endian;
use chrono::NaiveDateTime;
use diesel::query_builder::{AsChangeset, QueryFragment};
use diesel::{Insertable, QueryResult, QuerySource, Table};
use diesel::insertable::CanInsertInSingleQuery;
use diesel::sqlite::Sqlite;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::{UInt256, VarBytes};
use crate::crypto::byte_util::{BytesDecodable, Zeroable};
use crate::crypto::var_array::VarArray;
use crate::chain::block::{Block, BLOCK_UNKNOWN_HEIGHT, IBlock};
use crate::chain::chain::{Chain, LastPersistedChainInfo};
use crate::chain::chain_lock::ChainLock;
use crate::chain::checkpoint::Checkpoint;
use crate::chain::common::{MerkleTree, MerkleTreeHashFunction};
use crate::schema::blocks;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::block::{BlockEntity, NewBlockEntity};
use crate::storage::models::entity::{Entity, EntityConvertible, EntityUpdates, ModelConvertible};
use crate::util::crypto::x11_hash;

#[derive(Clone, Copy, Debug)]
pub struct MerkleBlock {
    pub base: Block,
    pub merkle_tree: MerkleTree,
}

impl EntityConvertible for MerkleBlock {
    fn to_entity<T, U>(&self) -> U
        where
            T: Table + QuerySource,
            T::FromClause: QueryFragment<Sqlite>,
            U: Insertable<T>,
            diesel::insertable::Values: QueryFragment<Sqlite> + CanInsertInSingleQuery<Sqlite> {
        let mut entity: NewBlockEntity = self.base.to_entity();
        let mut hashes_buffer = Vec::<u8>::new();
        self.merkle_tree.hashes
            .iter()
            .for_each(|hash| {
                hash.enc(&mut hashes_buffer);
            });
        entity.flags = Some(self.merkle_tree.flags.clone());
        entity.hashes = Some(hashes_buffer);
        entity
    }

    fn to_update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>>
        where
            T: Table,
            V: AsChangeset<Target=T> {
        let mut values = self.base.to_update_values();
        let mut hashes_buffer = Vec::<u8>::new();
        self.merkle_tree.hashes
            .iter()
            .for_each(|hash| {
                hash.enc(&mut hashes_buffer);
            });
        values.append(blocks::hashes.eq(hashes_buffer));
        values.append(blocks::flags.eq(&self.merkle_tree.flags));
        values
    }

    fn from_entity<T: Entity>(entity: T, context: &ManagedContext) -> QueryResult<Self> {
        todo!()
    }
}

// impl ModelConvertible for MerkleBlock {
//     type Item = ();
//
//     fn new_model<M>(&self) -> Self::Item {
//         Self {
//             base: Block {
//                 block_hash: Default::default(),
//                 version: 0,
//                 prev_block: Default::default(),
//                 merkle_root: Default::default(),
//                 timestamp: 0,
//                 target: 0,
//                 nonce: 0,
//                 total_transactions: 0,
//                 height: 0,
//                 chain: &(),
//                 chain_work: Default::default(),
//                 transaction_hashes: vec![],
//                 chain_locked: false,
//                 has_chain_lock_awaiting_saving: false,
//                 has_unverified_chain_lock: false,
//                 chain_lock_awaiting_processing: None,
//                 chain_lock_awaiting_saving: None
//             },
//             merkle_tree: MerkleTree {
//                 tree_element_count: 0,
//                 hashes: vec![],
//                 flags: vec![],
//                 merkle_root: Default::default(),
//                 hash_function: MerkleTreeHashFunction::SHA256_2
//             }
//         }
//     }
// }

impl IBlock for MerkleBlock {
    fn height(&self) -> u32 {
        self.base.height
    }

    fn set_height(&mut self, height: u32) {
        self.base.set_height(height);
    }

    fn block_hash(&self) -> UInt256 {
        self.base.block_hash
    }

    fn merkle_root(&self) -> UInt256 {
        self.base.merkle_root
    }

    fn prev_block(&self) -> UInt256 {
        self.base.prev_block
    }

    fn target(&self) -> u32 {
        self.base.target
    }

    fn to_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        self.base.to_data().enc(&mut buffer);
        if self.base.total_transactions > 0 {
            self.base.total_transactions.enc(&mut buffer);
            VarInt(self.merkle_tree.hashes.len() as u64).enc(&mut buffer);
            self.merkle_tree.hashes.iter().for_each(|hash| {
                hash.enc(&mut buffer);
            });
            VarInt(self.merkle_tree.flags.len() as u64).enc(&mut buffer);
            self.merkle_tree.flags.enc(&mut buffer);
        }
        buffer
    }

    fn timestamp(&self) -> u32 {
        self.base.timestamp()
    }

    fn transaction_hashes(&self) -> Vec<UInt256> {
        self.base.transaction_hashes()
    }

    fn chain_work(&self) -> UInt256 {
        self.base.chain_work()
    }

    fn set_chain_work(&mut self, chain_work: UInt256) {
        self.base.set_chain_work(chain_work);
    }

    fn chain_locked(&self) -> bool {
        self.base.chain_locked()
    }

    fn has_unverified_chain_lock(&self) -> bool {
        self.base.has_unverified_chain_lock()
    }

    fn chain_lock_awaiting_processing(&self) -> Option<&ChainLock> {
        self.base.chain_lock_awaiting_processing()
    }

    fn is_valid(&self) -> bool {
        self.base.is_valid()
    }

    fn can_calculate_difficulty_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> bool {
        self.base.can_calculate_difficulty_with_previous_blocks(previous_blocks)
    }

    fn verify_difficulty_with_previous_blocks(&self, previous_blocks: &HashMap<UInt256, dyn IBlock>) -> (bool, u32) {
        self.base.verify_difficulty_with_previous_blocks(previous_blocks)
    }
}

impl MerkleBlock {
    pub fn from_entity(entity: &BlockEntity, chain: &Chain) -> Option<Self> {
        let mut merkle_hashes = Vec::<UInt256>::new();
        if let Some(hashes) = &entity.hashes {
            (0..hashes.len())
                .step_by(std::mem::size_of::<UInt256>())
                .for_each(|offset| {
                    let hash = hashes[offset..offset+std::mem::size_of::<UInt256>()] as [u8; 32];
                    merkle_hashes.push(UInt256(hash));
                })
        }
        Some(Self {
            base: Block {
                block_hash: entity.block_hash,
                version: entity.version as u32,
                prev_block: entity.prev_block,
                merkle_root: entity.merkle_root,
                timestamp: entity.timestamp.timestamp() as u32,
                target: entity.target as u32,
                nonce: entity.nonce as u32,
                total_transactions: entity.total_transactions as u32,
                height: entity.height as u32,
                chain,
                chain_work: entity.chain_work,
                ..Default::default()
            },
            merkle_tree: MerkleTree {
                tree_element_count: 0,
                hashes: merkle_hashes,
                flags: entity.flags.unwrap_or(vec![]),
                hash_function: MerkleTreeHashFunction::SHA256_2
            }
        })
    }
}

impl MerkleBlock {
    pub fn init_with_message(bytes: &[u8], chain: &Chain) -> Option<Self> {
        if bytes.len() < 80 {
            return None;
        }
        let offset = &mut 0;
        let version = bytes.read_with::<u32>(offset, byte::LE)?;
        let prev_block = bytes.read_with::<UInt256>(offset, byte::LE)?;
        let merkle_root = bytes.read_with::<UInt256>(offset, byte::LE)?;
        let timestamp = bytes.read_with::<u32>(offset, byte::LE)?;
        let target = bytes.read_with::<u32>(offset, byte::LE)?;
        let nonce = bytes.read_with::<u32>(offset, byte::LE)?;
        let total_transactions = bytes.read_with::<u32>(offset, byte::LE)?;
        let hashes = if let Some(arr) = VarArray::<UInt256>::from_bytes(bytes, offset) {
            arr.1
        } else {
            vec![]
        };
        let merkle_flags_var_bytes = VarBytes::from_bytes(bytes, offset)?.1;

        let merkle_tree = MerkleTree {
            tree_element_count: total_transactions,
            hashes,
            flags: merkle_flags_var_bytes.to_vec(),
            hash_function: MerkleTreeHashFunction::SHA256_2
        };

        let mut buffer: Vec<u8> = Vec::new();
        version.enc(&mut buffer);
        prev_block.enc(&mut buffer);
        merkle_root.enc(&mut buffer);
        timestamp.enc(&mut buffer);
        target.enc(&mut buffer);
        nonce.enc(&mut buffer);

        let block_hash = UInt256::MIN;
        // TODO: bind x11

        Some(Self {
            base: Block {
                block_hash,
                version,
                prev_block,
                merkle_root,
                timestamp,
                target,
                nonce,
                total_transactions,
                height: u32::MAX,
                chain,
                ..Default::default()
            },
            merkle_tree
        })
    }

    // true if the given tx hash is included in the block
    pub fn contains_tx_hash(&self, tx_hash: UInt256) -> bool {
        self.merkle_tree.contains_hash(tx_hash)
    }

    /// returns an array of the matched tx hashes
    pub fn transaction_hashes(&self) -> Vec<UInt256> {
        self.merkle_tree.element_hashes()
    }

    pub fn is_merkle_tree_valid(&self) -> bool {
        self.merkle_tree.has_root(self.base.merkle_root)
    }

    // pub fn init_with_version(version: u32, block_hash: UInt256, prev_block: UInt256, timestamp: u32, merkle_root: UInt256, target: u32, chain_work: UInt256, height: u32, chain: &Chain) -> Self {
    //     Self {
    //         base: Block::in,
    //         merkle_tree: MerkleTree {}
    //     }
    // }

    // pub fn init_with_checkpoint(checkpoint: &Checkpoint, chain: &Chain) -> Self {
    //     let base = Block::init_with_version(2, checkpoint.timestamp, checkpoint.height, checkpoint.hash, UInt256::MIN, checkpoint.chain_work, checkpoint.merkle_root, checkpoint.target, chain);
    //     assert!(!checkpoint.chain_work.is_zero(), "Chain work must be set");
    //     let mut s = Self {
    //         base,
    //         merkle_tree: MerkleTree {
    //             tree_element_count: 0,
    //             hashes: vec![],
    //             flags: vec![],
    //             hash_function: MerkleTreeHashFunction::SHA256_2
    //         }
    //     }
    //
    //     if (!(self = [self initWithVersion:2 blockHash:checkpoint.blockHash prevBlock:UINT256_ZERO timestamp:checkpoint.timestamp merkleRoot:checkpoint.merkleRoot target:checkpoint.target chainWork:checkpoint.chainWork height:checkpoint.height onChain:chain])) return nil;
    //     NSAssert(uint256_is_not_zero(self.chainWork), @"block should have aggregate work set");
    //     return self;
    //
    // }

    pub fn new(version: u32,
               block_hash: UInt256,
               prev_block: UInt256,
               merkle_root: UInt256,
               timestamp: u32,
               target: u32,
               chain_work: UInt256,
               nonce: u32,
               total_transactions: u32,
               hashes: Vec<UInt256>,
               flags: Vec<u8>,
               height: u32,
               chain_lock: ChainLock,
               chain: &Chain) -> Self {
       Self {
           base: Block {
               block_hash,
               version,
               prev_block,
               merkle_root,
               timestamp,
               target,
               nonce,
               total_transactions,
               height,
               chain,
               chain_work,
               ..Default::default()
           },
           merkle_tree: MerkleTree {
               tree_element_count: total_transactions,
               hashes,
               flags,
               hash_function: MerkleTreeHashFunction::SHA256_2
           }
       }
        //
        // - (instancetype)initWithVersion:(uint32_t)version blockHash:(UInt256)blockHash prevBlock:(UInt256)prevBlock
        // merkleRoot:(UInt256)merkleRoot
        // timestamp:(uint32_t)timestamp
        // target:(uint32_t)target
        // chainWork:(UInt256)aggregateWork
        // nonce:(uint32_t)nonce
        // totalTransactions:(uint32_t)totalTransactions
        // hashes:(NSData *)hashes
        // flags:(NSData *)flags
        // height:(uint32_t)height
        // chainLock:(DSChainLock *)chainLock
        // onChain:(DSChain *)chain {
        //     if (!(self = [self initWithBlockHash:blockHash merkleRoot:merkleRoot totalTransactions:totalTransactions hashes:hashes flags:flags])) return nil;
        //
        //     self.version = version;
        //     self.prevBlock = prevBlock;
        //     self.merkleRoot = merkleRoot;
        //     self.timestamp = timestamp;
        //     self.target = target;
        //     self.nonce = nonce;
        //     self.height = height;
        //     self.chainWork = aggregateWork;
        //     [self setChainLockedWithChainLock:chainLock];
        //     self.chain = chain;
        //
        //     return self;
        // }

    }
    pub fn init_with_chain_info(version: u32, chain_info: &LastPersistedChainInfo, chain: &Chain) -> Self {
        last = MerkleBlock::new(2, self.last_persisted_chain_info.block_hash, UInt256::MIN, self.last_persisted_chain_info.block_timestamp, self.last_persisted_chain_info.block_height, self.last_persisted_chain_info.block_chain_work, self);
        Self {
            base: Block {
                block_hash: chain_info.block_hash,
                version,
                prev_block: UInt256::MIN,
                merkle_root,
                timestamp: chain_info.block_timestamp as u32,
                target: 0,
                nonce: 0,
                total_transactions: 0,
                height: 0,
                chain,
                ..Default::default()
            },
            merkle_tree: MerkleTree {}
        }
    }

    // - (instancetype)initWithVersion:(uint32_t)version blockHash:(UInt256)blockHash prevBlock:(UInt256)prevBlock timestamp:(uint32_t)timestamp height:(uint32_t)height chainWork:(UInt256)chainWork onChain:(DSChain *)chain {
    //
    // }
    // pub fn new(block_hash: UInt256, merkle_root: UInt256, total_transactions: u32, hashes: Vec<UInt256>, flags: Vec<u8>) -> Self {
    //     MerkleBlock {
    //         base: Block {
    //             block_hash,
    //             version: 0,
    //             prev_block: Default::default(),
    //             merkle_root,
    //             timestamp: 0,
    //             target: 0,
    //             nonce: 0,
    //             total_transactions,
    //             height: 0,
    //             chain: (),
    //             chain_work: Default::default(),
    //             transaction_hashes: vec![],
    //             chain_locked: false,
    //             chain_lock_awaiting_processing: None,
    //             chain_lock_awaiting_saving: None
    //         },
    //         merkle_tree: MerkleTree {
    //             tree_element_count: total_transactions,
    //             hashes,
    //             flags,
    //             merkle_root,
    //             hash_function: MerkleTreeHashFunction::SHA256_2
    //         }
    //     }
    // }


}

// todo: migrate to custom trait which allows passing of custom context, like Chain etc.
impl<'a> TryRead<'a, &'a Chain> for MerkleBlock {
    fn try_read(bytes: &'a [u8], ctx: &'a Chain) -> byte::Result<(Self, usize)> {
        let mut offset = &mut 0usize;
        assert!(bytes.len() < 80, "Merkle block message length less than 80");
        let version = bytes.read_with::<u32>(offset, byte::LE)?;
        let prev_block = bytes.read_with::<UInt256>(offset, byte::LE)?;
        let merkle_root = bytes.read_with::<UInt256>(offset, byte::LE)?;
        let timestamp = bytes.read_with::<u32>(offset, byte::LE)?;
        let target = bytes.read_with::<u32>(offset, byte::LE)?;
        let nonce = bytes.read_with::<u32>(offset, byte::LE)?;
        let merkle_tree = bytes.read_with::<MerkleTree>(offset, byte::LE)?;
        let height = BLOCK_UNKNOWN_HEIGHT as u32;
        let mut data = Vec::<u8>::new();
        version.enc(&mut data);
        prev_block.enc(&mut data);
        merkle_root.enc(&mut data);
        timestamp.enc(&mut data);
        target.enc(&mut data);
        nonce.enc(&mut data);
        let block_hash = x11_hash(&data);
        Ok((Self {
            base: Block {
                block_hash,
                version,
                prev_block,
                merkle_root,
                timestamp,
                target,
                nonce,
                total_transactions: merkle_tree.tree_element_count,
                height,
                chain,
                ..Default::default()
            },
            merkle_tree
        }, *offset))
    }
}
