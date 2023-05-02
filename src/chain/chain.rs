use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::time::{Duration, SystemTime};
use libp2p::futures::StreamExt;
use ring::rand::SystemRandom;
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::chain::common::{ChainType, LLMQType};
use crate::consensus::Encodable;
use crate::chain::block::block_position::BlockPosition;
use crate::chain::block::{Block, BLOCK_UNKNOWN_HEIGHT, DGW_PAST_BLOCKS_MAX, FullBlock, IBlock, MerkleBlock};
use crate::chain::chain_lock::ChainLock;
use crate::chain::chain_sync_phase::ChainSyncPhase;
use crate::chain::checkpoint::Checkpoint;
use crate::chain::ext::store::Store;
use crate::chain::ext::sync_progress::SyncProgress;
use crate::chain::network::bloom_filter::{BLOOM_UPDATE_ALL, BloomFilter};
use crate::chain::network::peer::{Peer, WEEK_TIME_INTERVAL};
use crate::chain::options::options::Options;
use crate::chain::options::sync_type::SyncType;
use crate::chain::params::{DEFAULT_FEE_PER_B, MAX_FEE_PER_B, MIN_FEE_PER_B, Params, TX_UNCONFIRMED};
use crate::chain::tx::transaction::ITransaction;
use crate::chain::wallet::account::Account;
use crate::chain::wallet::wallet::{BIP39_CREATION_TIME, Wallet};
use crate::chain::spork;
use crate::crypto::byte_util::{AsBytes, Zeroable};
use crate::util::data_ops::short_hex_string_from;
use crate::crypto::UTXO;
use crate::crypto::UInt256;
use crate::{dapi, derivation};
use crate::chain::dispatch_context::DispatchContext;
use crate::chain::ext::identities::Identities;
use crate::chain::ext::invitations::Invitations;
use crate::chain::wallet::extension::masternodes::Masternodes;
use crate::derivation::derivation_path::{DerivationPath, IDerivationPath};
use crate::derivation::derivation_path_kind::DerivationPathKind;
use crate::derivation::sequence_gap_limit::SequenceGapLimit;
use crate::environment::Environment;
use crate::keychain::keychain::Keychain;
use crate::manager::{AuthenticationManager, GovernanceSyncManager, IdentitiesManager, MasternodeManager, PeerManager, TransactionManager};
use crate::network::network_context::NetworkContext;
use crate::notifications::{Notification, NotificationCenter};
use crate::platform::platform::Platform;
use crate::storage::context::StoreContext;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::manager::managed_context_type::ManagedContextType;
use crate::storage::models::chain::block::BlockEntity;
use crate::user_defaults::UserDefaults;
use crate::util::base58;
use crate::util::time::TimeUtil;

const CHAIN_WALLETS_KEY: &str = "CHAIN_WALLETS_KEY";
const CHAIN_STANDALONE_DERIVATIONS_KEY: &str = "CHAIN_STANDALONE_DERIVATIONS_KEY";
const REGISTERED_PEERS_KEY: &str = "REGISTERED_PEERS_KEY";
const CHAIN_VOTING_KEYS_KEY: &str = "CHAIN_VOTING_KEYS_KEY";
const LAST_SYNCED_GOVERANCE_OBJECTS: &str = "LAST_SYNCED_GOVERANCE_OBJECTS";
const LAST_SYNCED_MASTERNODE_LIST: &str = "LAST_SYNCED_MASTERNODE_LIST";
const SYNC_STARTHEIGHT_KEY: &str = "SYNC_STARTHEIGHT";
const TERMINAL_SYNC_STARTHEIGHT_KEY: &str = "TERMINAL_SYNC_STARTHEIGHT";
const FEE_PER_BYTE_KEY: &str = "FEE_PER_BYTE";

/// This is about the time if we consider a block every 10 mins (for 500 blocks)
pub const HEADER_WINDOW_BUFFER_TIME: u64 = WEEK_TIME_INTERVAL / 2;

pub const KEEP_RECENT_TERMINAL_BLOCKS: u32 = 4 * 576 * 8 + 100; // 40000;
pub const KEEP_RECENT_SYNC_BLOCKS: u32 = 0; // 100;
const BLOCK_NO_FORK_DEPTH: u32 = 25;


/// Chain Sync Info
#[derive(Debug)]
pub struct LastPersistedChainInfo {
    /// The hash of the last persisted sync block. The sync block itself most likely is not persisted
    pub block_hash: UInt256,
    /// The height of the last persisted sync block. The sync block itself most likely is not persisted
    pub block_height: u32,
    /// The timestamp of the last persisted sync block. The sync block itself most likely is not persisted
    pub block_timestamp: u64,
    /// The locators of the last persisted chain sync block. The sync block itself most likely is not persisted
    pub locators: Option<Vec<UInt256>>,
    pub block_chain_work: UInt256,
}

impl Default for LastPersistedChainInfo {
    fn default() -> Self {
        Self {
            locators: None,
            block_hash: UInt256::MIN,
            block_height: 0,
            block_chain_work: UInt256::MIN,
            block_timestamp: 0
        }
    }
}


#[derive(Default)]
pub struct Chain {
    pub network_context: NetworkContext,
    pub store_context: StoreContext,
    platform: Option<&'static Platform>,

    pub sync_phase: ChainSyncPhase,
    pub chain_sync_weight: f64,
    pub terminal_header_sync_weight: f64,
    pub masternode_list_sync_weight: f64,
    pub last_persisted_chain_info: LastPersistedChainInfo,
    pub params: Params,

    pub(self) spork_manager: Option<spork::Manager>,
    pub(self) masternode_manager: Option<MasternodeManager>,
    pub(self) peer_manager: Option<PeerManager>,
    pub(self) transaction_manager: Option<TransactionManager>,
    pub(self) governance_sync_manager: Option<GovernanceSyncManager>,
    pub(self) identities_manager: Option<IdentitiesManager>,
    pub authentication_manager: &'static AuthenticationManager,
    pub environment: &'static Environment,

    dapi_client: Option<dapi::Client>,

    /// An array of known hardcoded checkpoints for the chain
    pub checkpoints: Vec<Checkpoint>,
    checkpoints_by_hash_dictionary: HashMap<UInt256, Checkpoint>,
    checkpoints_by_height_dictionary: HashMap<u32, Checkpoint>,

    pub last_sync_block: Option<&'static dyn IBlock>,
    pub last_terminal_block: Option<&'static dyn IBlock>,
    /// The last known orphan on the chain. An orphan is a block who's parent is currently not known
    pub last_orphan: Option<&'static dyn IBlock>,

    /// The last chainLock known by the chain at the heighest height
    pub last_chain_lock: Option<&'static ChainLock>,

    terminal_headers_override_use_checkpoint: Option<&'static Checkpoint>,
    sync_headers_override_use_checkpoint: Option<&'static Checkpoint>,
    last_checkpoint: Option<&'static Checkpoint>,
    pub last_sync_block_height: u32,

    pub orphans: HashMap<UInt256, &'static dyn IBlock>,
    pub wallets: Vec<&'static Wallet>,

    /// The height of the best block
    pub best_block_height: u32,

    pub estimated_block_heights: HashMap<u32, Vec<Peer>>,
    pub transaction_hash_heights: HashMap<UInt256, u32>,
    pub transaction_hash_timestamps: HashMap<UInt256, u64>,
    pub terminal_blocks: HashMap<UInt256, &'static dyn IBlock>,
    pub sync_blocks: HashMap<UInt256, &'static dyn IBlock>,
    pub unique_id: String,
    best_estimated_block_height: Option<u32>,
    pub options: Options,
    viewing_account: Option<Account>,
    pub derivation_path_factory: derivation::factory::Factory,
    chain_synchronization_block_zones: Option<HashSet<u16>>,
    chain_synchronization_fingerprint: Option<Vec<u8>>,

    insight_verified_blocks_by_hash_dictionary: HashMap<UInt256, &'static dyn IBlock>,

    pub(crate) chain_sync_start_height: u32,
    pub(crate) terminal_sync_start_height: u32,

    pub(crate) fee_per_byte: u64,

    pub is_transient: bool,

    last_notified_block_did_change: f64,
    last_notified_block_did_change_timer: Option<os_timer::Timer>,

    got_sporks_at_chain_sync_start: bool,

    pub last_relay_time: u64,

    pub masternode_base_block_hash: UInt256,
    pub total_governance_objects_count: u32,
}

impl Debug for Chain {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.params.fmt(f)
    }
}

impl<'a> Default for &'a Chain {
    fn default() -> Self {
        Self::default()
    }
}

impl Chain {
    pub(crate) fn update_last_chain_lock_if_need(&mut self, lock: &ChainLock) {
        if self.last_chain_lock.is_none() || self.last_chain_lock.unwrap().height < lock.height {
            self.last_chain_lock = Some(lock);
        }
    }
}

impl Chain {
    pub(crate) fn set_min_protocol_version(&self, p0: u32) {
        todo!("Save it to keychain and recreate ChainParams from the keychain at initialization")
    }

    pub fn system_random(&self) -> &SystemRandom {
        &self.environment.system_random
    }
}

// ChainManager
impl Chain {
    pub(crate) fn chain_will_start_syncing_blockchain(&self) {
        if !self.got_sporks_at_chain_sync_start {
            // get the sporks early on
            self.spork_manager().get_sporks();
        }
    }

    pub(crate) fn chain_should_start_syncing_blockchain(&mut self, peer: &mut Peer) {
        DispatchContext::main_context().queue(|| NotificationCenter::post(Notification::ChainSyncDidStart(self, peer)));
        DispatchContext::network_context().queue(|| {
           if self.sync_phase != ChainSyncPhase::ChainSync && self.sync_phase != ChainSyncPhase::Synced && self.needs_initial_terminal_headers_sync() {
               // masternode list should be synced first and the masternode list is old
               self.sync_phase = ChainSyncPhase::InitialTerminalBlocks;
               peer.send_getheaders_message_with_locators(self.terminal_block_locators_array(), UInt256::MIN);
           } else if self.options.sync_type.bits() & SyncType::MasternodeList.bits() != 0 &&
               (self.masternode_manager().last_masternode_list_block_height() < self.last_terminal_block_height() - 8 ||
                   self.masternode_manager().last_masternode_list_block_height() == u32::MAX) {
               self.sync_phase = ChainSyncPhase::InitialTerminalBlocks;
               self.masternode_manager().start_sync();
           } else {
               self.sync_phase = ChainSyncPhase::ChainSync;
               let starting_devnet_sync = self.is_devnet_any() && self.last_sync_block_height() < 5;
               let cutoff_time = self.earliest_wallet_creation_time() - HEADER_WINDOW_BUFFER_TIME;
               if starting_devnet_sync || (self.last_sync_block_timestamp() >= cutoff_time as u32 && self.should_request_merkle_blocks_for_zone_after_height(self.last_sync_block_height())) {
                   peer.send_getblocks_message_with_locators(self.chain_sync_block_locator_array(), UInt256::MIN);
               } else {
                   peer.send_getheaders_message_with_locators(self.chain_sync_block_locator_array(), UInt256::MIN);
               }
           }
        });
    }

    /// Info
    pub fn chain_sync_start_height_key(&self) -> String {
        format!("{}_{}", SYNC_STARTHEIGHT_KEY, self.unique_id)
    }

    pub fn terminal_sync_start_height_key(&self) -> String {
        format!("{}_{}", TERMINAL_SYNC_STARTHEIGHT_KEY, self.unique_id)
    }

    pub(crate) fn reset_chain_sync_start_height(&mut self) {
        if self.chain_sync_start_height == 0 {
            self.chain_sync_start_height = UserDefaults::integer_for_key(self.chain_sync_start_height_key().as_str()).unwrap_or(0) as u32
        }
        if self.chain_sync_start_height == 0 {
            self.chain_sync_start_height = self.last_sync_block_height();
            UserDefaults::set_integer_for_key(self.chain_sync_start_height_key().as_str(), self.chain_sync_start_height as i32);
        }
    }

    pub fn restart_chain_sync_start_height(&mut self) {
        self.chain_sync_start_height = 0;
        UserDefaults::set_integer_for_key(self.chain_sync_start_height_key().as_str(), 0);
    }

    pub(crate) fn reset_terminal_sync_start_height(&mut self) {
        if self.terminal_sync_start_height == 0 {
            self.terminal_sync_start_height = UserDefaults::integer_for_key(self.terminal_sync_start_height_key().as_str()).unwrap_or(0) as u32
        }
        if self.terminal_sync_start_height == 0 {
            self.terminal_sync_start_height = self.last_terminal_block_height();
            UserDefaults::set_integer_for_key(self.terminal_sync_start_height_key().as_str(), self.terminal_sync_start_height as i32);
        }
    }

    pub fn restart_chain_terminal_sync_start_height(&mut self) {
        self.terminal_sync_start_height = 0;
        UserDefaults::set_integer_for_key(self.terminal_sync_start_height_key().as_str(), 0);
    }

    fn chain_did_set_block_height(&self, height: u32, timestamp: u64, tx_hashes: &Vec<UInt256>, updated_tx_hashes: &Vec<UInt256>) {
        self.transaction_manager().chain_did_set_block_height(height, timestamp, tx_hashes, updated_tx_hashes);
    }
    fn chain_received_orphan_block(&mut self, block: &dyn IBlock, peer: &mut Peer) {
        // ignore orphans older than one week ago
        if block.timestamp() < (SystemTime::seconds_since_1970() - WEEK_TIME_INTERVAL) as u32 {
            return
        }
        // call getblocks, unless we already did with the previous block, or we're still downloading the chain
        if self.last_sync_block_height() >= peer.last_block_height && (self.last_orphan.is_none() || self.last_orphan.unwrap().block_hash() != block.prev_block()) {
            peer.send_getblocks_message_with_locators(self.chain_sync_block_locator_array(), UInt256::MIN);
        }
    }

    fn chain_was_extended_with_block(&mut self, block: &mut dyn IBlock, peer: &mut Peer) {
        if self.options.sync_type.contains(SyncType::MasternodeList) {
            // make sure we care about masternode lists
            self.masternode_manager().get_current_masternode_list_with_safety_delay(3);
        }
    }

    fn chain_finished_syncing_transactions_and_blocks(&mut self, peer: &mut Peer, on_main_chain: bool) {
        if on_main_chain && self.peer_manager().is_download_peer(peer) {
            self.last_relay_time = SystemTime::seconds_since_1970();
        }
        println!("chain finished syncing");
        self.chain_sync_start_height = 0;
        self.sync_phase = ChainSyncPhase::Synced;
        self.transaction_manager().fetch_mempool_from_network();
        self.spork_manager().get_sporks();
        self.governance_sync_manager().start_governance_sync();
        if self.options.sync_type.contains(SyncType::MasternodeList) {
            // make sure we care about masternode lists
            self.masternode_manager().start_sync();
        }
    }

    fn chain_finished_syncing_initial_headers(&mut self, peer: &mut Peer, on_main_chain: bool) {
        if on_main_chain && self.peer_manager().is_download_peer(peer) {
            self.last_relay_time = SystemTime::seconds_since_1970();
        }
        self.peer_manager().chain_sync_stopped();
        if self.options.sync_type.contains(SyncType::MasternodeList) {
            // make sure we care about masternode lists
            self.masternode_manager().start_sync();
        }
    }

    fn chain_bad_block_received_from_peer(&mut self, peer: &mut Peer) {
        println!("peer at address {} is misbehaving", peer.host());
        self.peer_manager().peer_misbehaving(peer, "Bad block received from peer");
    }
}

impl PartialEq<Self> for Chain {
    fn eq(&self, other: &Self) -> bool {
        self == other || other.r#type().genesis_hash().eq(&self.r#type().genesis_hash())
    }
}

impl Chain {
    pub fn view_context(&self) -> &ManagedContext {
        self.store_context.context_for(ManagedContextType::View)
    }

    pub fn peer_context(&self) -> &ManagedContext {
        self.store_context.context_for(ManagedContextType::Peer)
    }

    pub fn chain_context(&self) -> &ManagedContext {
        self.store_context.context_for(ManagedContextType::Chain)
    }

    pub fn masternodes_context(&self) -> &ManagedContext {
        self.store_context.context_for(ManagedContextType::Masternodes)
    }

    pub fn platform_context(&self) -> &ManagedContext {
        self.store_context.context_for(ManagedContextType::Platform)
    }
}

impl Chain {
    /// Managers

    pub fn masternode_manager(&self) -> &MasternodeManager {
        &self.masternode_manager.unwrap()
    }

    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager.unwrap()
    }

    pub fn transaction_manager(&self) -> &TransactionManager {
        &self.transaction_manager.unwrap()
    }

    pub fn governance_sync_manager(&self) -> &GovernanceSyncManager {
        &self.governance_sync_manager.unwrap()
    }

    pub fn spork_manager(&self) -> &spork::Manager {
        &self.spork_manager.unwrap()
    }

    pub fn identities_manager(&self) -> &IdentitiesManager {
        &self.identities_manager.unwrap()
    }


    pub fn is_mainnet(&self) -> bool {
        self.r#type() == ChainType::MainNet
    }

    pub fn is_testnet(&self) -> bool {
        self.r#type() == ChainType::TestNet
    }

    pub fn is_devnet_any(&self) -> bool {
        !self.is_mainnet() && !self.is_testnet()
    }

    pub fn is_evolution_enabled(&self) -> bool {
        false
        //self.is_devnet_any() || self.is_testnet()
    }

    pub fn r#type(&self) -> ChainType {
        self.params.chain_type
    }

    pub fn base_reward(&self) -> u64 {
        self.params.base_reward
    }

    /// Keychain Strings

    pub fn chain_wallets_key(&self) -> String {
        format!("{}_{}", CHAIN_WALLETS_KEY, self.unique_id)
    }

    pub fn chain_standalone_derivation_paths_key(&self) -> String {
        format!("{}_{}", CHAIN_STANDALONE_DERIVATIONS_KEY, self.unique_id)
    }

    pub fn registered_peers_key(&self) -> String {
        format!("{}_{}", REGISTERED_PEERS_KEY, self.unique_id)
    }

    pub fn voting_keys_key(&self) -> String {
        format!("{}_{}", CHAIN_VOTING_KEYS_KEY, self.unique_id)
    }

    pub fn transaction_version(&self) -> u16 {
        match self.r#type() {
            ChainType::MainNet => 1,
            ChainType::TestNet => 1,
            ChainType::DevNet(_) => 3
        }
    }

    pub fn peer_misbehaving_threshold(&self) -> u16 {
        match self.r#type() {
            ChainType::MainNet => 20,
            ChainType::TestNet => 40,
            ChainType::DevNet(_) => 3
        }
    }

    /// required for SPV wallets
    pub fn syncs_blockchain(&self) -> bool {
        self.options.sync_type.bits() & SyncType::NeedsWalletSyncType.bits() == 0
        // !(self.options.sync_type & SyncType::NeedsWalletSyncType)
    }

    pub fn needs_initial_terminal_headers_sync(&mut self) -> bool {
        self.estimated_block_height() != self.last_terminal_block_height()
    }

    /// This is a time interval since 1970
    pub fn earliest_wallet_creation_time(&self) -> u64 {
        if self.wallets.is_empty() {
            BIP39_CREATION_TIME as u64
        } else {
            let mut time_interval = SystemTime::seconds_since_1970();
            for mut wallet in self.wallets {
                if time_interval > wallet.wallet_creation_time() {
                    time_interval = wallet.wallet_creation_time();
                }
            }
            time_interval
        }
    }

    pub fn start_sync_from_time(&self) -> u64 {
        if self.syncs_blockchain() {
            self.earliest_wallet_creation_time()
        } else {
            self.checkpoints.last().unwrap().timestamp.into()
        }
    }

    pub fn chain_tip(&self) -> String {
        short_hex_string_from(self.last_terminal_block.map_or(UInt256::MIN, |b| b.block_hash()).as_bytes())
    }

    pub fn should_process_quorum_of_type(&self, llmq_type: LLMQType) -> bool {
        self.r#type().should_process_llmq_of_type(llmq_type)
    }

    /// Standalone Derivation Paths

    pub fn has_a_standalone_derivation_path(&mut self) -> bool {
        !self.viewing_account().fund_derivation_paths.is_empty()
    }

    pub fn viewing_account(&mut self) -> &Account {
        self.viewing_account.map_or({
            let acc = Account::init_as_view_only_with_account_number(self.chain_context());
            self.viewing_account = Some(acc);
            &acc
        }, |acc| &acc)
    }



    pub fn retrieve_standalone_derivation_paths(&mut self) {
        if let Ok(standalone_identifiers) = Keychain::get_array::<String>(self.chain_standalone_derivation_paths_key(), vec!["String".to_string()]) {
            for identifier in standalone_identifiers {
                if let Some(derivation_path) = DerivationPath::init_with_extended_public_key_identifier(identifier, self) {
                    self.add_standalone_derivation_path(Box::new(derivation_path));
                }
            }
        }
    }

    pub fn unregister_all_standalone_derivation_paths(&mut self) {
        if let Some(mut acc) = &self.viewing_account {
            acc.fund_derivation_paths.iter_mut().for_each(|mut derivation_path| {
                self.unregister_standalone_derivation_path(derivation_path);
            });
        }
    }

    pub fn unregister_standalone_derivation_path(&mut self, derivation_path: &mut Box<dyn IDerivationPath>) {
        // TODO: delete from keychain
        if let Ok(mut arr) = Keychain::get_array::<String>(self.chain_standalone_derivation_paths_key(), vec!["String".to_string()]) {
            if let Some(unique_id) = derivation_path.standalone_extended_public_key_unique_id() {
                if let Some(pos) = arr.iter().position(|p| *p == unique_id) {
                    arr.remove(pos);
                }
                Keychain::set_array(arr, self.chain_standalone_derivation_paths_key(), false)
                    .expect("Can't store standalone derivation paths");
                self.viewing_account().remove_derivation_path(*derivation_path);
                DispatchContext::main_context().queue(|| {
                    NotificationCenter::post(Notification::ChainStandaloneDerivationPathsDidChange(self));
                });
            }
        }
    }

    pub fn add_standalone_derivation_path(&mut self, derivation_path: Box<dyn IDerivationPath>) {
        if let Some(mut acc) = &self.viewing_account {
            acc.add_derivation_path(derivation_path);
        }
    }

    pub fn register_standalone_derivation_path(&mut self, derivation_path: &mut Box<dyn IDerivationPath>) {
        // TODO: isKindOfClass
        if derivation_path.kind() == DerivationPathKind::Funds && !self.viewing_account().fund_derivation_paths.contains(&derivation_path.deref()) {
            self.add_standalone_derivation_path(*derivation_path);
        }
        let mut arr = Keychain::get_array::<String>(self.chain_standalone_derivation_paths_key(), vec!["String".to_string()]).unwrap_or(vec![]);
        if let Some(id) = derivation_path.standalone_extended_public_key_unique_id() {
            arr.push(id);
            Keychain::set_array(arr, self.chain_standalone_derivation_paths_key(), false).expect("Keychain is unavailable");
            DispatchContext::main_context().queue(||
                NotificationCenter::post(Notification::ChainStandaloneDerivationPathsDidChange(self)));
        }
    }

    pub fn standalone_derivation_paths(&mut self) -> &Vec<Box<dyn IDerivationPath>> {
        &self.viewing_account().fund_derivation_paths
    }


    /// Probabilistic Filters
    pub fn bloom_filter_with_false_positive_rate(&mut self, false_positive_rate: f64, tweak: u32) -> BloomFilter {
        let mut all_addresses = HashSet::new();
        let mut all_utxos = HashSet::new();

        for wallet in self.wallets {
            // every time a new wallet address is added, the bloom filter has to be rebuilt, and each address is only used for
            // one transaction, so here we generate some spare addresses to avoid rebuilding the filter each time a wallet
            // transaction is encountered during the blockchain download
            let _ = wallet.register_addresses_with_gap_limit(SequenceGapLimit::Initial.default(), SequenceGapLimit::Initial.unused(), SequenceGapLimit::Initial.dashpay(), false);
            let _ = wallet.register_addresses_with_gap_limit(SequenceGapLimit::Initial.default(), SequenceGapLimit::Initial.unused(), SequenceGapLimit::Initial.dashpay(), true);
            let mut addresses: HashSet<String> = HashSet::new();
            addresses.extend(wallet.all_receive_addresses());
            addresses.extend(wallet.all_change_addresses());
            all_addresses.extend(addresses);
            all_utxos.extend(wallet.unspent_outputs());
            all_addresses.extend(wallet.provider_owner_addresses());
            all_addresses.extend(wallet.provider_voting_addresses());
            all_addresses.extend(wallet.provider_operator_addresses());
        }

        for mut derivation_path in self.standalone_derivation_paths() {
            let addresses = derivation_path.register_addresses();
            all_addresses.extend(addresses);
        }
        self.clear_orphans();
        let mut o: Option<UTXO> = None;
        let d: Option<Vec<u8>> = None;
        let mut i = 0;
        let mut elem_count = all_addresses.len() + all_utxos.len();
        let mut inputs = Vec::new();
        for wallet in self.wallets {
            for tx in wallet.all_transactions() {
                // find TXOs spent within the last 100 blocks
                if tx.block_height() != TX_UNCONFIRMED as u32 && tx.block_height() + 100 < self.last_sync_block_height {
                    //println!("Not adding transaction {} inputs to bloom filter", tx.tx_hash());
                    // the transaction is confirmed for at least 100 blocks, then break
                    continue;
                }
                //println!("Adding transaction {} inputs to bloom filter", tx.tx_hash());
                i = 0;
                for input in tx.inputs() {
                    let hash = input.input_hash;
                    let n = input.index;
                    let oo = UTXO { hash, n };
                    o = Some(oo);
                    if let Some(t) = wallet.transaction_for_hash(&hash) {
                        let outputs = t.outputs();
                        if let Some(out) = outputs.get(n as usize) {
                            if let Some(address) = &out.address {
                                if oo.n < outputs.len() as u32 && wallet.contains_address(address) {
                                    inputs.push(oo);
                                }
                            }
                        }
                    }
                    elem_count += 1;
                }
            }
        }
        let mut filter = BloomFilter::init_with_false_positive_rate(false_positive_rate, if elem_count < 200 { 300 } else { elem_count as u64 + 100 }, tweak, BLOOM_UPDATE_ALL);
        // add addresses to watch for tx receiveing money to the wallet
        all_addresses.iter().for_each(|addr| {
            if let Ok(d) = base58::from_check(addr.as_str()) {
                if d.len() == 160 / 8 + 1 {
                    filter.insert_data_if_needed(&mut d[1..d.len()].to_vec());
                }
            }
        });
        // add UTXOs to watch for tx sending money from the wallet
        all_utxos.iter().for_each(|utxo| {
            // TODO: dsutxo_data??
            let mut writer: Vec<u8> = Vec::new();
            utxo.enc(writer);
            filter.insert_data_if_needed(&mut writer);
        });
        // also add TXOs spent within the last 100 blocks
        inputs.iter().for_each(|utxo| {
            let mut writer: Vec<u8> = Vec::new();
            utxo.enc(writer);
            filter.insert_data_if_needed(&mut writer);
        });
        filter
    }

    pub fn can_construct_a_filter(&mut self) -> bool {
        self.has_a_standalone_derivation_path() || self.has_a_wallet()
    }

    /// Checkpoints

    pub fn block_height_has_checkpoint(&self, block_height: u32) -> bool {
        if let Some(checkpoint) = self.last_checkpoint_on_or_before_height(block_height) {
            checkpoint.height == block_height
        } else {
            false
        }
    }

    pub fn last_checkpoint(&mut self) -> Option<&Checkpoint> {
        self.last_checkpoint.or({
            let last = self.checkpoints.last();
            if let Some(checkpoint) = last {
                self.last_checkpoint = Some(checkpoint);
            }
            last
        })
    }

    pub fn last_checkpoint_on_or_before_height(&self, height: u32) -> Option<&Checkpoint> {
        let genesis_height = if self.is_devnet_any() { 1 } else { 0 };
        // if we don't have any blocks yet, use the latest checkpoint that's at least a week older than earliest_key_time
        for i in (genesis_height..self.checkpoints.len()).rev() {
            if let Some(checkpoint) = self.checkpoints.get(i) {
                if checkpoint.height == genesis_height as u32 || !self.syncs_blockchain() || checkpoint.height <= height {
                    return Some(checkpoint);
                }
            }
        }
        None
    }

    pub fn last_checkpoint_on_or_before_timestamp(&self, timestamp: u32) -> Option<&Checkpoint> {
        let genesis_height = if self.is_devnet_any() { 1 } else { 0 };
        // if we don't have any blocks yet, use the latest checkpoint that's at least a week older than earliest_key_time
        for i in (genesis_height..self.checkpoints.len()).rev() {
            if let Some(checkpoint) = self.checkpoints.get(i) {
                if checkpoint.height == genesis_height as u32 || !self.syncs_blockchain() || checkpoint.timestamp <= timestamp {
                    return Some(checkpoint);
                }
            }
        }
        None
    }

    pub fn last_checkpoint_having_masternode_list(&self) -> Option<&Checkpoint> {
        if let Some(pair) = self.checkpoints_by_height_dictionary.iter().filter(|(height, checkpoint)| !checkpoint.masternode_list_path.is_empty()).last() {
            Some(pair.1)
        } else {
            None
        }
    }
    pub fn checkpoint_for_block_hash(&self, block_hash: &UInt256) -> Option<&Checkpoint> {
        self.checkpoints_by_hash_dictionary.get(block_hash)
    }

    pub fn checkpoint_for_block_height(&self, block_height: &u32) -> Option<&Checkpoint> {
        self.checkpoints_by_height_dictionary.get(block_height)
    }

    pub fn checkpoints_by_hash_dictionary(&mut self) -> &HashMap<UInt256, Checkpoint> {
        if self.checkpoints_by_hash_dictionary.is_empty() {
            self.sync_blocks();
        }
        &self.checkpoints_by_hash_dictionary
    }

    pub fn checkpoints_by_height_dictionary(&mut self) -> &HashMap<u32, Checkpoint> {
        if self.checkpoints_by_height_dictionary.is_empty() {
            self.sync_blocks();
        }
        &self.checkpoints_by_height_dictionary
    }

    pub fn use_checkpoint_before_or_on_height_for_terminal_blocks_sync(&mut self, block_height: u32) {
        if let Some(checkpoint) = self.last_checkpoint_on_or_before_height(block_height) {
            self.terminal_headers_override_use_checkpoint = Some(checkpoint);
        }
    }

    pub fn use_checkpoint_before_or_on_height_for_syncing_blocks_sync(&mut self, block_height: u32) {
        if let Some(checkpoint) = self.last_checkpoint_on_or_before_height(block_height) {
            self.sync_headers_override_use_checkpoint = Some(checkpoint);
        }
    }

    /// Wallet

    pub fn has_a_wallet(&self) -> bool {
        self.wallets.len() > 0
    }


    pub fn unregister_all_wallets(&mut self) {
        self.wallets.iter_mut().for_each(|wallet| {
            self.unregister_wallet(wallet);
        });
    }

    pub fn unregister_all_wallets_missing_extended_public_keys(&mut self) {
        self.wallets.iter_mut().for_each(|wallet| {
            if wallet.has_an_extended_public_key_missing() {
                self.unregister_wallet(wallet);
            }
        });
    }

    pub fn unregister_wallet(&mut self, wallet: &mut Wallet) {
        assert_eq!(wallet.chain, self, "the wallet you are trying to remove is not on this chain");
        wallet.wipe_blockchain_info(self.chain_context());
        wallet.wipe_wallet_info();
        if let Some(pos) = self.wallets.iter().position(|x| *x == wallet) {
            self.wallets.remove(pos);
        }
        let mut key_chain_array = Keychain::get_array::<String>(self.chain_wallets_key(), vec!["String".to_string()]).unwrap_or(vec![]);
        if let Some(pos) = key_chain_array.iter().position(|x| *x == wallet.unique_id_string) {
            key_chain_array.remove(pos);
        }
        let _ = Keychain::set_array(key_chain_array, self.chain_wallets_key(), false);
        DispatchContext::main_context().queue(|| NotificationCenter::post(Notification::WalletsDidChange(self)));
    }

    pub fn add_wallet(&mut self, wallet: &Wallet) -> bool {
        if self.wallets.iter().filter(|w| w.unique_id_string == wallet.unique_id_string).count() > 0 {
            false
        } else {
            self.wallets.push(wallet);
            true
        }
    }

    pub fn register_wallet(&mut self, wallet: &Wallet) {
        let is_first = self.wallets.is_empty();
        if !self.wallets.contains(&wallet) {
            self.add_wallet(wallet);
        }
        if is_first {
            // this is the first wallet, we should reset the last block height to the most recent checkpoint.
            self.last_sync_block = None; // it will lazy load later
        }
        let unique_id = wallet.unique_id_string.clone();
        let mut key_chain_array = Keychain::get_array::<String>(self.chain_wallets_key(), vec!["String".to_string()]).unwrap_or(vec![]);
        if !key_chain_array.contains(&unique_id) {
            key_chain_array.push(unique_id);
            let _ = Keychain::set_array(key_chain_array, self.chain_wallets_key(), false);
            DispatchContext::main_context().queue(||
                NotificationCenter::post(Notification::WalletsDidChange(self)));
        }
    }

    pub fn retrieve_wallets(&mut self) {
        match Keychain::get_array::<String>(self.chain_wallets_key(), vec!["String".to_string()]) {
            Ok(wallet_identifiers) => {
                wallet_identifiers.iter().for_each(|&unique_id| {
                    self.add_wallet(&Wallet::init_with_unique_id(unique_id, self));
                });
                // we should load blockchain identies after all wallets are in the chain, as blockchain
                // identities might be on different wallets and have interactions between each other
                self.wallets.iter().for_each(|wallet| wallet.load_blockchain_identities());
            },
            Err(err) => {
                println!("Error retrievient wallets {:?}", err);
            }
        }
    }

    /// Blocks
    pub fn recent_blocks(&self) -> HashMap<UInt256, &dyn IBlock> {
        self.sync_blocks.clone()
    }

    pub fn last_chain_sync_block_on_or_before_timestamp(&self, timestamp: u32) -> Option<&dyn IBlock> {
        let mut b = self.last_sync_block.clone();
        while b.is_some() && b.unwrap().height() > 0 && b.unwrap().timestamp() >= timestamp {
            b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
        }
        if b.is_none() {
            if let Some(checkpoint) = self.last_checkpoint_on_or_before_timestamp(timestamp) {
                b = Some(&MerkleBlock::init_with_checkpoint(checkpoint, self));
            }
        }
        b
    }

    pub fn last_block_on_or_before_timestamp(&self, timestamp: u32) -> Option<&dyn IBlock> {
        let mut b = self.last_terminal_block.clone();
        let mut use_sync_blocks_now = b != self.last_terminal_block;
        while b.is_some() && b.unwrap().height() > 0 && b.unwrap().timestamp() >= timestamp {
            if !use_sync_blocks_now {
                b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
            }
            if b.is_none() {
                use_sync_blocks_now = !use_sync_blocks_now;
                b = if use_sync_blocks_now { &self.sync_blocks } else { &self.terminal_blocks }.get(&b.unwrap().prev_block()).copied();
            }

            b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
        }
        if b.is_none() {
            if let Some(checkpoint) = self.last_checkpoint_on_or_before_timestamp(timestamp) {
                b = Some(&MerkleBlock::init_with_checkpoint(checkpoint, self));
            }
        }
        b
    }

    pub fn set_last_terminal_block_from_checkpoints(&mut self) {
        if let Some(checkpoint) = &self.terminal_headers_override_use_checkpoint.or(self.last_checkpoint) {
            if self.terminal_blocks.contains_key(&checkpoint.hash) {
                self.last_terminal_block = self.sync_blocks.get(&checkpoint.hash).copied();
            } else {
                let block = MerkleBlock::init_with_checkpoint(checkpoint, &self);
                self.last_terminal_block = Some(&block);
                self.terminal_blocks.insert(checkpoint.hash, &block);
            }
        }
        if let Some(block) = &self.last_terminal_block {
            println!("last terminal block at height {} chosen from checkpoints (hash is {})", block.height(), block.block_hash());
        }
    }

    pub fn set_last_sync_block_from_checkpoints(&mut self) {
        let mut checkpoint: Option<&Checkpoint> = None;
        if let Some(cp) = &self.sync_headers_override_use_checkpoint {
            checkpoint = Some(cp);
        } else if self.options.sync_from_genesis() {
            let genesis_height = if self.is_devnet_any() { 1 } else { 0 };
            checkpoint = self.checkpoints.get(genesis_height);
        } else if self.options.should_sync_from_height {
            checkpoint = self.last_checkpoint_on_or_before_height(self.options.sync_from_height);
        } else {
            let start_sync_time = self.start_sync_from_time();
            let timestamp = if start_sync_time as u32 == BIP39_CREATION_TIME { BIP39_CREATION_TIME } else { (start_sync_time - HEADER_WINDOW_BUFFER_TIME) as u32 };
            checkpoint = self.last_checkpoint_on_or_before_timestamp(timestamp);
        }
        if let Some(cp) = checkpoint {
            self.last_sync_block = self.sync_blocks.get(&cp.hash).or({
                let b: &dyn IBlock = &MerkleBlock::init_with_checkpoint(cp, self);
                self.sync_blocks.insert(cp.hash.clone(), b);
                Some(&b)
            }).copied();

            // if let Some(b) = self.sync_blocks.get(&cp.hash) {
            //     self.last_sync_block = Some(b);
            // } else {
            //     let b = MerkleBlock::init_with_checkpoint(cp, self);
            //     self.last_sync_block = Some(&b);
            //     self.sync_blocks.insert(cp.hash.clone(), &b);
            // }
        }
        if let Some(b) = &self.last_sync_block {
            println!("last sync block at height {} chosen from checkpoints for chain {:?} (hash is {})", b.height(), self.r#type(), b.block_hash());
        }
    }

    pub fn last_sync_block_dont_use_checkpoints(&mut self) -> Option<&dyn IBlock> {
        self.last_sync_block_with_use_checkpoints(false)
    }

    pub fn last_sync_block(&mut self) -> Option<&dyn IBlock> {
        self.last_sync_block_with_use_checkpoints(true)
    }

    pub fn last_sync_block_with_use_checkpoints(&mut self, use_checkpoints: bool) -> Option<&dyn IBlock> {
        self.last_sync_block.or_else(|| {
            let mut last: Option<&dyn IBlock> = None;
            if !self.last_persisted_chain_info.block_hash.is_zero() &&
                !self.last_persisted_chain_info.block_chain_work.is_zero() &&
                self.last_persisted_chain_info.block_height != BLOCK_UNKNOWN_HEIGHT as u32 {
                last = Some(&MerkleBlock::init_with_chain_info(2, &self.last_persisted_chain_info, self));
                self.last_sync_block = last;
            }
            if self.last_sync_block.is_none() && use_checkpoints {
                println!("No last Sync Block, setting it from checkpoints");
                self.set_last_sync_block_from_checkpoints();
            }
            last
        })
    }

    pub fn sync_blocks(&mut self) -> &HashMap<UInt256, &dyn IBlock> {
        if !self.sync_blocks.is_empty() {
            return &self.sync_blocks;
        }
        // todo!("Retrieve from local DB");
        self.chain_context().perform_block_and_wait(|context| {
            if self.sync_blocks.is_empty() {
                //self.sync_blocks.clear();
                if !self.last_persisted_chain_info.block_hash.is_zero() {
                    // [[DSMerkleBlock alloc] initWithVersion:2 blockHash:self.lastPersistedChainSyncBlockHash prevBlock:UINT256_ZERO timestamp:self.lastPersistedChainSyncBlockTimestamp height:self.lastPersistedChainSyncBlockHeight chainWork:self.lastPersistedChainSyncBlockChainWork onChain:self]
                    let new_block = MerkleBlock::init_with_chain_info(2, &self.last_persisted_chain_info, self);
                    self.sync_blocks.insert(self.last_persisted_chain_info.block_hash, &new_block);
                    self.checkpoints_by_hash_dictionary = HashMap::new();
                    self.checkpoints_by_height_dictionary = HashMap::new();
                    self.checkpoints.iter().for_each(|&checkpoint| {
                        let checkpoint_hash = checkpoint.hash;
                        self.sync_blocks.insert(checkpoint_hash, &Block::init_with_checkpoint(&checkpoint, self));
                        self.checkpoints_by_height_dictionary.insert(checkpoint.height, checkpoint.clone());
                        self.checkpoints_by_hash_dictionary.insert(checkpoint_hash, checkpoint.clone());
                    });
                }
            }
        });
        &self.sync_blocks
    }

    pub fn chain_sync_block_locator_array(&mut self) -> Vec<UInt256> {
        if self.last_sync_block.is_some() && self.last_sync_block.unwrap().height() == 1 && self.is_devnet_any() {
            self.block_locator_array_for_block(self.last_sync_block)
        } else if let Some(locators) = &self.last_persisted_chain_info.locators {
            locators.clone()
        } else {
            let locators: Vec<UInt256> = self.block_locator_array_on_or_before_timestamp(BIP39_CREATION_TIME, false);
            self.last_persisted_chain_info.locators = Some(locators);
            locators.clone()
        }
    }

    pub fn block_locator_array_on_or_before_timestamp(&self, timestamp: u32, include_headers: bool) -> Vec<UInt256> {
        let block = if include_headers {
            self.last_block_on_or_before_timestamp(timestamp)
        } else {
            self.last_chain_sync_block_on_or_before_timestamp(timestamp)
        };
        self.block_locator_array_for_block(block)
    }

    /// this is used as part of a getblocks or getheaders request
    pub fn block_locator_array_for_block(&self, block: Option<&dyn IBlock>) -> Vec<UInt256> {
        // append 10 most recent block checkpointHashes, decending, then continue appending, doubling the step back each time,
        // finishing with the genesis block (top, -1, -2, -3, -4, -5, -6, -7, -8, -9, -11, -15, -23, -39, -71, -135, ..., 0)
        let mut locators = Vec::<UInt256>::new();
        let mut step = 1i32;
        let mut start = 0i32;
        let mut b: Option<&dyn IBlock> = block;
        let mut last_height = block.map_or(0, |b| b.height());
        while b.is_some() && b.unwrap().height() > 0 {
            locators.push(b.unwrap().block_hash());
            last_height = b.unwrap().height();
            start += 1;
            if start >= 10 {
                step *= 2;
            }
            let mut i = 0;
            while b.is_some() && i < step {
                let prev = b.unwrap().prev_block();
                b = self.sync_blocks.get(&prev).copied();
                if b.is_none() {
                    b = self.terminal_blocks.get(&prev).copied();
                }
                i += 1;
            }
        }
        let mut last_checkpont: Option<Checkpoint> = None;
        // add the last checkpoint we know about previous to this block
        for checkpoint in self.checkpoints {
            if checkpoint.height < last_height && checkpoint.timestamp < b.unwrap().timestamp() {
                last_checkpont = Some(checkpoint);
            } else {
                break;
            }
        }
        if let Some(last) = last_checkpont {
            locators.push(last.hash);
        }
        locators
    }

    pub fn block_for_block_hash(&self, block_hash: &UInt256) -> Option<&dyn IBlock> {
        self.sync_blocks.get(block_hash).copied()
            .or(self.terminal_blocks.get(block_hash).copied())
            .or(
                if self.params.allow_insight_blocks_for_verification() {
                    self.insight_verified_blocks_by_hash_dictionary.get(block_hash).copied()
                } else {
                    None
                }
            )
    }

    pub fn recent_terminal_block_for_block_hash(&self, block_hash: &UInt256) -> Option<&dyn IBlock> {
        let mut b: Option<&dyn IBlock> = self.last_terminal_block.clone();
        let mut use_sync_blocks_now = false;
        while b.is_some() && b.unwrap().height() > 0 && b.unwrap().block_hash() != *block_hash {
            if !use_sync_blocks_now {
                b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
            }
            if b.is_none() {
                use_sync_blocks_now = true;
            }
            if use_sync_blocks_now {
                b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
            }
        }
        b
    }

    pub fn recent_sync_block_for_block_hash(&mut self, block_hash: &UInt256) -> Option<&dyn IBlock> {
        let mut b: Option<&dyn IBlock> = if let Some(last) = self.last_sync_block_dont_use_checkpoints() {
            Some(last)
        } else {
            None
        };
        while b.is_some() && b.unwrap().height() > 0 && b.unwrap().block_hash() != *block_hash {
            b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
        }
        b
    }

    pub fn block_at_height(&self, height: u32) -> Option<&dyn IBlock> {
        let mut b: Option<&dyn IBlock> = self.last_terminal_block.clone();
        while b.is_some() && b.unwrap().height() > height {
            b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
        }
        if b.is_some() && b.unwrap().height() != height {
            let mut b: Option<&dyn IBlock> = None;
            if self.last_sync_block.is_some() {
                b = self.last_sync_block.clone();
                while b.is_some() && b.unwrap().height() > height {
                    b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
                }
                if b.unwrap().height() != height {
                    return None;
                }
            }
        }
        b
    }

    pub fn block_at_height_or_last_terminal(&mut self, height: u32) -> Option<&dyn IBlock> {
        let mut block = self.block_at_height(height);
        if block.is_none() && height > self.last_terminal_block_height() {
            block = self.last_terminal_block.clone();
        }
        block
    }

    pub fn block_from_chain_tip(&self, blocks_ago: u32) -> Option<&dyn IBlock> {
        let mut b = self.last_terminal_block.clone();
        let mut count = 0;
        let mut use_sync_blocks_now = false;
        while b.is_some() && b.unwrap().height() > 0 && count < blocks_ago {
            if !use_sync_blocks_now {
                b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
            }
            if b.is_none() {
                use_sync_blocks_now = true;
            }
            if use_sync_blocks_now {
                b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
            }
            count += 1;
        }
        b
    }


    /// From Insight on Testnet
    pub fn block_until_get_insight_for_block_hash(&self, block_hash: &UInt256) {
        todo!("Impl semaphore")
    }

    pub fn add_insight_verified_block(&mut self, block: &dyn IBlock, block_hash: UInt256) {
        if self.params.allow_insight_blocks_for_verification() {
            self.insight_verified_blocks_by_hash_dictionary.insert(block_hash, block);
        }
    }

    pub fn add_mined_full_block(&mut self, block: FullBlock) -> bool {
        //assert!(block.transaction_hashes(), "Block must have txHashes");
        let tx_hashes = block.transaction_hashes();
        let block_hash = block.block_hash();
        let prev_block = block.prev_block();

        if self.sync_blocks.get(&prev_block).is_none() || !self.terminal_blocks.get(&prev_block).is_none() {
            return false;
        }
        if self.last_sync_block().unwrap().block_hash() != self.sync_blocks.get(&prev_block).unwrap().block_hash() {
            return false;
        }
        if self.last_terminal_block().unwrap().block_hash() != self.terminal_blocks.get(&prev_block).unwrap().block_hash() {
            return false;
        }
        self.sync_blocks.insert(block_hash, &block);
        self.last_sync_block = Some(&block);
        self.terminal_blocks.insert(block_hash, &block);
        self.last_terminal_block = Some(&block);
        let tx_time = (block.timestamp() + self.terminal_blocks.get(&prev_block).unwrap().timestamp()) / 2;
        self.set_block_height(block.height(), tx_time as u64, tx_hashes);

        if block.height() > self.estimated_block_height() {
            self.best_estimated_block_height = Some(block.height());
            self.save_block_locators();
            self.save_terminal_blocks();
            // notify that transaction confirmations may have changed
            self.notify_blocks_and_tip_changed();
        }
        true
    }

    /// TRUE if it was added to the end of the chain
    pub fn add_block(&mut self, block: &mut dyn IBlock, is_header_only: bool, peer: Option<&mut Peer>) -> bool {
        if peer.is_some() && self.sync_phase == ChainSyncPhase::Offline {
            println!("Block was received from peer after reset, ignoring it");
            return false;
        }
        // All blocks will be added from same delegateQueue
        let tx_hashes = block.transaction_hashes();
        let block_hash = block.block_hash();
        let prev_block = block.prev_block();
        let mut prev: Option<&dyn IBlock> = None;
        let mut block_position = BlockPosition::Orphan;
        let mut phase = self.sync_phase.clone();
        if phase == ChainSyncPhase::InitialTerminalBlocks {
            // In this phase all received blocks are treated as terminal blocks
            prev = self.terminal_blocks.get(&prev_block).copied();
            if prev.is_some() {
                block_position = BlockPosition::Terminal;
            }
        } else {
            prev = self.sync_blocks.get(&prev_block).copied();
            if prev.is_none() {
                prev = self.terminal_blocks.get(&prev_block).copied();
                if prev.is_some() {
                    block_position = BlockPosition::Terminal;
                }
            } else if self.terminal_blocks.get(&prev_block).is_some() {
                // lets see if we are at the chain tip
                if self.terminal_blocks.get(&block_hash).is_some() {
                    // we already had this block, we are not at chain tip
                    block_position = BlockPosition::Sync;
                } else {
                    // we do not have this block as a terminal block, we are at chain tip
                    block_position = BlockPosition::TerminalSync;
                }
            } else {
                block_position = BlockPosition::Sync;
            }
        }

        if prev.is_none() {
            // header is an orphan
            println!("{:?} relayed orphan block {}, previous {}, height {}, last block is {}, lastBlockHeight {}, time {}",
                     peer,
                     block.block_hash(),
                     block.prev_block(),
                     block.height(),
                     self.last_terminal_block.unwrap().block_hash(),
                     self.last_sync_block_height,
                     block.timestamp());

            if let Some(peer) = peer {
                self.chain_received_orphan_block(block, peer);
                peer.received_orphan_block();
            }
            // orphans are indexed by prev_block instead of block_hash
            self.orphans.insert(prev_block, block.clone());
            self.last_orphan = Some(block.clone());
            return false;
        }

        let mut sync_done = false;
        block.set_height(prev.unwrap().height() + 1);
        let target = UInt256::set_compact_le(block.target() as i32);
        assert!(!prev.unwrap().chain_work().is_zero(), "previous block should have aggregate work set");
        block.set_chain_work(prev.unwrap().chain_work().add_le(target.inverse().divide_le(target.add_one_le()).add_one_le()));
        assert!(!block.chain_work().is_zero(), "block should have aggregate work set");
        let mut tx_time = (block.timestamp() + prev.unwrap().timestamp()) / 2;

        if block_position.contains(BlockPosition::Terminal) && (block.height() % 10000 == 0 || (block.height() == self.estimated_block_height() && block.height() % 100 == 0)) {
            // free up some memory from time to time
            let mut b: Option<&dyn IBlock> = Some(block);
            let mut i = 0;
            while b.is_some() && i < KEEP_RECENT_TERMINAL_BLOCKS {
                b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
                i += 1;
            }
            let mut blocks_to_remove = Vec::<UInt256>::new();
            while b.is_some() {
                blocks_to_remove.push(b.unwrap().block_hash());
                b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
            }
            blocks_to_remove.iter().for_each(|hash| {
                self.terminal_blocks.remove(hash);
            });
        }

        if block_position.contains(BlockPosition::Sync) && block.height() % 1000 == 0 {
            // free up some memory from time to time
            let mut b: Option<&dyn IBlock> = Some(block);
            let mut i = 0;
            while b.is_some() && i < KEEP_RECENT_SYNC_BLOCKS {
                b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
                i += 1;
            }
            let mut blocks_to_remove = Vec::<UInt256>::new();
            while b.is_some() {
                blocks_to_remove.push(b.unwrap().block_hash());
                b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
            }
            blocks_to_remove.iter().for_each(|hash| {
                self.sync_blocks.remove(hash);
            });
        }

        // verify block difficulty if block is past last checkpoint
        let last_checkpoint = self.last_checkpoint();
        let mut equivalent_terminal_block: Option<&dyn IBlock> = None;
        if block_position.contains(BlockPosition::Sync) && self.last_sync_block_height + 1 >= last_checkpoint.unwrap().height {
            equivalent_terminal_block = self.terminal_blocks.get(&block_hash).copied();
        }

        if equivalent_terminal_block.is_none() &&
            (block_position.contains(BlockPosition::Terminal) || block.can_calculate_difficulty_with_previous_blocks(&self.sync_blocks)) {
            // no need to check difficulty if we already have terminal blocks
            let mut found_difficulty = 0;
            if (block.height() > self.params.minimum_difficulty_blocks) &&
                (block.height() > (last_checkpoint.unwrap().height + DGW_PAST_BLOCKS_MAX as u32)) {
                let (verified, found) = block.verify_difficulty_with_previous_blocks(if block_position.contains(BlockPosition::Terminal) { &self.terminal_blocks } else { &self.sync_blocks });
                found_difficulty = found as i32;
                if !verified {
                    println!("{:?} relayed block with invalid difficulty height {} target {} foundTarget {}, blockHash: {}", peer, block.height(), block.target(), found_difficulty, block_hash);
                    if let Some(peer) = peer {
                        self.chain_bad_block_received_from_peer(peer);
                    }
                    return false;
                }
            }
            let difficulty = UInt256::set_compact_le(block.target() as i32);
            if block.block_hash() > difficulty {
                println!("{:?} relayed block with invalid block hash target {} block_hash: {}, difficulty: {} <-> {}", peer, block.target(), block.block_hash(), found_difficulty, difficulty);
                if let Some(peer) = peer {
                    self.chain_bad_block_received_from_peer(peer);
                }
                return false;
            }
        }
        let checkpoint = self.checkpoints_by_height_dictionary.get(&block.height());
        if !equivalent_terminal_block.is_none() && (checkpoint.is_some() && block.block_hash() != checkpoint.unwrap().hash) {
            // verify block chain checkpoints
            println!("{:?} relayed a block that differs from the checkpoint at height {}, blockHash: {}, expected: {}", peer, block.height(), block_hash, checkpoint.unwrap().hash);
            if let Some(peer) = peer {
                self.chain_bad_block_received_from_peer(peer);
            }
            return false;
        }
        let mut on_main_chain = false;

        if (phase == ChainSyncPhase::ChainSync || phase == ChainSyncPhase::Synced) && block.prev_block() == self.last_sync_block_hash() {
            // new block extends sync chain
            self.sync_blocks.insert(block_hash, block);
            if equivalent_terminal_block.is_some() && equivalent_terminal_block.unwrap().chain_locked() && !block.chain_locked() {
                block.set_chain_locked_with_equivalent_block(equivalent_terminal_block.unwrap());
            }
            self.last_sync_block = Some(block.clone());

            if equivalent_terminal_block.is_none() && block.prev_block() == self.last_terminal_block.unwrap().block_hash() {
                self.terminal_blocks.insert(block_hash, block);
                self.last_terminal_block = Some(block.clone());
            }
            if let Some(peer) = peer {
                peer.current_block_height = block.height(); // might be download peer instead
            }
            if block.height() == self.estimated_block_height() {
                sync_done = true;
            }
            self.set_block_height(block.height(), tx_time as u64, tx_hashes);
            on_main_chain = true;
            if self.block_height_has_checkpoint(block.height()) || (block.height() % 1000 == 0 && block.height() + BLOCK_NO_FORK_DEPTH < self.last_terminal_block_height() && !self.masternode_manager().has_masternode_list_currently_being_saved()) {
                self.save_block_locators();
            }
        } else if block.prev_block() == self.last_terminal_block().unwrap().block_hash() {
            // new block extends terminal chain
            self.terminal_blocks.insert(block_hash, block);
            self.last_terminal_block = Some(block.clone());
            if let Some(peer) = peer {
                peer.current_block_height = block.height(); //might be download peer instead
            }
            if block.height() == self.estimated_block_height() {
                sync_done = true;
            }
            on_main_chain = true;
        } else if (phase == ChainSyncPhase::ChainSync || phase == ChainSyncPhase::Synced) && self.sync_blocks.get(&block_hash).is_some() {
            self.sync_blocks.insert(block_hash, block);
            if equivalent_terminal_block.is_some() && equivalent_terminal_block.unwrap().chain_locked() && !block.chain_locked() {
                block.set_chain_locked_with_equivalent_block(equivalent_terminal_block.unwrap());
            }
            if let Some(peer) = peer {
                peer.current_block_height = block.height(); //might be download peer instead
            }
            let mut b = self.last_sync_block();
            while b.is_some() && b.unwrap().height() > block.height() {
                b = self.sync_blocks.get(&b.unwrap().prev_block()).copied(); // is block in main chain?
            }
            if b.is_some() && b.unwrap().block_hash() == block.block_hash() {
                // if it's not on a fork, set block heights for its transactions
                self.set_block_height(block.height(), tx_time as u64, tx_hashes);
                if block.height() == self.last_sync_block_height() {
                    self.last_sync_block = Some(block.clone());
                }
            }
        } else if self.terminal_blocks.get(&block_hash).is_some() && block_position.contains(BlockPosition::Terminal) {
            // we already have the block (or at least the header)
            self.terminal_blocks.insert(block_hash, block);
            if let Some(peer) = peer {
                peer.current_block_height = block.height(); //might be download peer instead
            }
            let mut b = self.last_terminal_block().clone();
            while b.is_some() && b.unwrap().height() > block.height() {
                b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied(); // is block in main chain?
            }
            if b.is_some() && b.unwrap().block_hash() == block.block_hash() {
                // if it's not on a fork, set block heights for its transactions
                self.set_block_height(block.height(), tx_time as u64, tx_hashes);
                if block.height() == self.last_terminal_block_height() {
                    self.last_terminal_block = Some(block.clone());
                }
            }
        } else {
            // new block is on a fork
            if block.height() <= self.last_checkpoint().unwrap().height {
                // fork is older than last checkpoint
                println!("ignoring block on fork older than most recent checkpoint, fork height: {}, blockHash: {}", block.height(), block_hash);
                return true;
            }
            if block.height() <= self.last_chain_lock.unwrap().height {
                println!("ignoring block on fork when main chain is chainlocked: {}, blockHash: {}", block.height(), block_hash);
                return true;
            }
            println!("potential chain fork to height {} block_position {:?}", block.height(), block_position);
            if !block_position.contains(BlockPosition::Sync) {
                // this is only a reorg of the terminal blocks
                self.terminal_blocks.insert(block_hash, block);
                if self.last_terminal_block().unwrap().chain_work() >= block.chain_work() {
                    // if fork is shorter than main chain, ignore it for now
                    return true;
                }
                println!("found potential chain fork on height {}", block.height());
                let mut b: Option<&dyn IBlock> = Some(block);
                let mut b2 = self.last_terminal_block();
                while b.is_some() && b2.is_some() && b.unwrap().block_hash() != b2.unwrap().block_hash() && b2.unwrap().chain_locked() {
                    // walk back to where the fork joins the main chain
                    b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
                    if b.unwrap().height() < b2.unwrap().height() {
                        b2 = self.terminal_blocks.get(&b2.unwrap().prev_block()).copied();
                    }
                }
                if b.unwrap().block_hash() != b2.unwrap().block_hash() && b2.unwrap().chain_locked() {
                    //intermediate chain locked block
                    println!("no reorganizing chain to height {} because of chainlock at height {}", block.height(), b2.unwrap().height());
                    return true;
                }
                println!("reorganizing terminal chain from height {}, new height is {}", b.unwrap().height(), block.height());
                self.last_terminal_block = Some(block.clone());
                if let Some(peer) = peer {
                    // might be download peer instead
                    peer.current_block_height = block.height();
                }
                if block.height() == self.estimated_block_height() {
                    sync_done = true;
                }
            } else {
                if phase == ChainSyncPhase::ChainSync || phase == ChainSyncPhase::Synced {
                    self.terminal_blocks.insert(block_hash, block);
                }
                self.sync_blocks.insert(block_hash, block);
                if let Some(equivalent) = equivalent_terminal_block {
                    if equivalent.chain_locked() && !block.chain_locked() {
                        block.set_chain_locked_with_equivalent_block(equivalent);
                    }
                }
                if self.last_sync_block.unwrap().chain_work() >= block.chain_work() {
                    // if fork is shorter than main chain, ignore it for now
                    return true;
                }
                println!("found sync chain fork on height {}", block.height());
                if (phase == ChainSyncPhase::ChainSync || phase == ChainSyncPhase::Synced) && self.last_terminal_block().unwrap().chain_work() < block.chain_work() {
                    let mut b: Option<&dyn IBlock> = Some(block);
                    let mut b2 = self.last_terminal_block().clone();
                    while b.is_some() && b2.is_some() && b.unwrap().block_hash() != b2.unwrap().block_hash() && !b2.unwrap().chain_locked() {
                        // walk back to where the fork joins the main chain
                        b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
                        if b.unwrap().height() < b2.unwrap().height() {
                            b2 = self.terminal_blocks.get(&b2.unwrap().prev_block()).copied();
                        }
                    }
                    if b.unwrap().block_hash() != b2.unwrap().block_hash() && b2.unwrap().chain_locked() {
                        // intermediate chain locked block
                    } else {
                        println!("reorganizing terminal chain from height {}, new height is {}", b.unwrap().height(), block.height());
                        self.last_terminal_block = Some(block);
                        if let Some(peer) = peer {
                            peer.current_block_height = block.height(); // might be download peer instead
                        }
                    }
                }
                let mut b = block.clone();
                let mut b2 = self.last_sync_block();
                while b.is_some() && b2.is_some() && b.unwrap().block_hash() != b2.unwrap().block_hash() && !b2.unwrap().chain_locked() {
                    // walk back to where the fork joins the main chain
                    b = self.sync_blocks.get(&b.unwrap().prev_block());
                    if b.unwrap().height() < b2.unwrap().height() {
                        b2 = self.sync_blocks.get(&b2.unwrap().prev_block()).copied();
                    }
                }
                if b.block_hash() != b2.unwrap().block_hash() && b2.unwrap().chain_locked() {
                    // intermediate chain locked block
                    println!("no reorganizing sync chain to height {} because of chainlock at height {}", block.height(), b2.unwrap().height());
                    return true;
                }
                println!("reorganizing sync chain from height {}, new height is {}", b.height(), block.height());
                let mut tx_hashes = Vec::<UInt256>::new();
                // mark transactions after the join point as unconfirmed
                for wallet in self.wallets {
                    for tx in wallet.all_transactions() {
                        if tx.block_height() <= b.height() {
                            break;
                        }
                        tx_hashes.push(tx.tx_hash());
                    }
                }
                self.set_block_height(TX_UNCONFIRMED as u32, 0, tx_hashes);
                b = block;
                while b.height() > b2.unwrap().height() {
                    // set transaction heights for new main chain
                    self.set_block_height(b.height(), tx_time as u64, b.transaction_hashes());
                    b = self.sync_blocks.get(&b.unwrap().prev_block());
                    tx_time = (b.timestamp() + self.sync_blocks.get(&b.prev_block()).unwrap().timestamp() ) / 2;
                }
                self.last_sync_block = Some(block);
                if block.height() == self.estimated_block_height() {
                    sync_done = true;
                }
            }
        }
        if block_position.contains(BlockPosition::Terminal) && checkpoint.is_some() && checkpoint == self.last_checkpoint_having_masternode_list() {
            self.masternode_manager().load_file_distributed_masternode_lists();
        }
        let mut saved_block_locators = false;
        let mut saved_terminal_blocks = false;
        if sync_done {
            // chain download is complete
            if block_position.contains(BlockPosition::Terminal) {
                self.save_terminal_blocks();
                saved_terminal_blocks = true;
                if let Some(peer) = peer {
                    self.chain_finished_syncing_initial_headers(peer, on_main_chain);
                }
                DispatchContext::main_context().queue(||
                    NotificationCenter::post(Notification::ChainInitialHeadersDidFinishSyncing(self)));
            }
            if block_position.contains(BlockPosition::Sync) && (phase == ChainSyncPhase::ChainSync || phase == ChainSyncPhase::Synced) {
                // we should only save
                self.save_block_locators();
                saved_block_locators = true;
                if let Some(peer) = peer {
                    self.chain_finished_syncing_transactions_and_blocks(peer, on_main_chain);
                }
                DispatchContext::main_context().queue(||
                    NotificationCenter::post(Notification::ChainBlocksDidFinishSyncing(self)));
            }
        }
        if (block_position.contains(BlockPosition::Terminal) && block.height() > self.estimated_block_height()) ||
            (block_position.contains(BlockPosition::Sync) && block.height() >= self.last_terminal_block_height()) {
            self.best_estimated_block_height = Some(block.height());
            if peer.is_some() && block_position.contains(BlockPosition::Sync) && !saved_block_locators {
                self.save_block_locators();
            }
            if block_position.contains(BlockPosition::Terminal) && !saved_terminal_blocks {
                self.save_terminal_blocks();
            }

            if let Some(peer) = peer {
                self.chain_was_extended_with_block(block, peer);
            }
            self.setup_block_change_timer(|| {
                self.notify_blocks_and_tip_changed();
            });
        } else {
            self.setup_block_change_timer(|| {
                if block_position.contains(BlockPosition::Terminal) {
                    NotificationCenter::post(Notification::ChainTerminalBlocksDidChange(self));
                }
                if block_position.contains(BlockPosition::Sync) {
                    NotificationCenter::post(Notification::ChainSyncBlocksDidChange(self));
                }
            });
        }
        // check if the next block was received as an orphan
        if self.last_terminal_block() == Some(block) {
            if let Some(mut b) = self.orphans.get(&block_hash) {
                self.orphans.remove(&block_hash);
                self.add_block(&mut b, true, peer); // revisit this
            }
        }
        true
    }

    fn setup_block_change_timer(&mut self, completion: impl Fn()) {
        // notify that transaction confirmations may have changed
        let timestamp = SystemTime::seconds_since_1970() as f64;

        if self.last_notified_block_did_change == 0.0 || timestamp - self.last_notified_block_did_change > 0.1 {
            self.last_notified_block_did_change = timestamp;

            if self.last_notified_block_did_change_timer.is_some() {
                // self.last_notified_block_did_change_timer.invalidate();
                self.last_notified_block_did_change_timer = Some(unsafe {
                    os_timer::Timer::uninit()
                });
            }
            completion();
        } else if !self.last_notified_block_did_change_timer.is_none() {
            let mut timer = unsafe {
                os_timer::Timer::uninit()
            };
            let timer = os_timer::Timer::new(os_timer::Callback::closure(completion));

            self.last_notified_block_did_change_timer = timer;
            if let Some(timer) = &timer {
                timer.schedule_once(Duration::from_secs(1));
            }

            // self.last_notified_block_did_change_timer = [NSTimer timerWithTimeInterval:1 repeats:NO block:^(NSTimer *_Nonnull timer) {
            //     completion();
            // }];
            // [[NSRunLoop mainRunLoop] addTimer:self.lastNotifiedBlockDidChangeTimer forMode:NSRunLoopCommonModes];
        }

    }

    fn notify_blocks_and_tip_changed(&self) {
        DispatchContext::main_context().queue(|| {
            NotificationCenter::post(Notification::ChainTipDidUpdate(self));
            NotificationCenter::post(Notification::ChainSyncBlocksDidChange(self));
            NotificationCenter::post(Notification::ChainTerminalBlocksDidChange(self));
        });
    }

    pub fn terminal_blocks(&mut self) -> HashMap<UInt256, &dyn IBlock> {
        if !self.terminal_blocks.is_empty() {
            self.checkpoints_by_hash_dictionary = HashMap::new();
            self.checkpoints_by_height_dictionary = HashMap::new();
            return self.terminal_blocks.clone();
        }
        // TODO: retrieve from local DB
        //[self.chainManagedObjectContext performBlockAndWait:^{
        if self.terminal_blocks.is_empty() {
           self.terminal_blocks = HashMap::new();
            self.checkpoints_by_hash_dictionary = HashMap::new();
            self.checkpoints_by_height_dictionary = HashMap::new();
            // add checkpoints to the block collection
            self.checkpoints.iter().for_each(|&checkpoint| {
                let checkpoint_hash = checkpoint.hash;
                self.terminal_blocks.insert(checkpoint_hash, &Block::init_with_checkpoint(&checkpoint, self));
                self.checkpoints_by_height_dictionary.insert(checkpoint.height, checkpoint.clone());
                self.checkpoints_by_hash_dictionary.insert(checkpoint_hash, checkpoint.clone());
            });
            if let Ok(entities) = BlockEntity::get_last_terminal_blocks(self.r#type(), KEEP_RECENT_TERMINAL_BLOCKS, self.chain_context()) {
                entities.iter().for_each(|entity| {
                    if let Some(b) = MerkleBlock::from_entity(entity, self) {
                        self.terminal_blocks.insert(b.block_hash(), &b);
                    }
                });
            }
        }
        //}];
        self.terminal_blocks.clone()
    }

    pub fn last_terminal_block(&mut self) -> Option<&dyn IBlock> {
        self.last_terminal_block.or({
            if let Ok(entity) = BlockEntity::get_last_terminal_block(self.r#type(), self.chain_context()) {
                if let Some(b) = MerkleBlock::from_entity(&entity, self) {
                    self.last_terminal_block = Some(&b);
                    println!("last terminal block at height {} recovered from db (hash is {})", b.height(), b.block_hash());
                }
            }
            if self.last_terminal_block.is_none() {
                // if we don't have any headers yet, use the latest checkpoint
                // let last_checkpoint = if let Some(point) = &self.terminal_headers_override_use_checkpoint {
                //     point.clone()
                // } else {
                //     self.last_checkpoint.clone()
                // };
                let last_sync_block_height = self.last_sync_block_height;
                let last_checkpoint = &self.terminal_headers_override_use_checkpoint.or(self.last_checkpoint);

                if last_checkpoint.is_some() && last_checkpoint.unwrap().height >= last_sync_block_height {
                    self.set_last_terminal_block_from_checkpoints();
                } else {
                    self.last_terminal_block = self.last_sync_block.clone();
                }
            }
            if let Some(b) = &self.last_terminal_block {
                if b.height() > self.estimated_block_height() {
                    self.best_estimated_block_height = Some(b.height());
                }
            }
            self.last_terminal_block.clone()
        })
    }

    pub fn terminal_block_locators_array(&self) -> Vec<UInt256> {
        let mut locators = Vec::<UInt256>::new();
        let mut step = 1;
        let mut start = 0;
        let mut b = self.last_terminal_block.clone();
        let mut last_height = 0;//b.height;
        let terminal_blocks = self.terminal_blocks.clone();
        while b.is_some() && b.unwrap().height() > 0 {
            locators.push(b.unwrap().block_hash());
            last_height = b.unwrap().height();
            start += 1;
            if start >= 10 {
                step *= 2;
            }
            let mut i = 0;
            while b.is_some() && i < step {
                b = terminal_blocks.get(&b.unwrap().prev_block()).copied();
                i += 1;
            }
        }
        // then add the last checkpoint we know about previous to this header
        if let Some(last_checkpoint) = self.checkpoints.iter().find(|checkpoint| checkpoint.height < last_height) {
            locators.push(last_checkpoint.hash);
        }
        locators
    }

    /// Orphans

    pub fn clear_orphans(&mut self) {
        // clear out orphans that may have been received on an old filter
        self.orphans.clear();
        self.last_orphan = None;
    }

    /// ChainLocks

    pub fn add_chain_lock(&mut self, chain_lock: &mut ChainLock) -> bool {
        let terminal_block_opt = self.terminal_blocks.get(&chain_lock.block_hash);
        if let Some(mut terminal_block) = terminal_block_opt {
            terminal_block.set_chain_locked_with_chain_lock(chain_lock);
            if terminal_block.chain_locked() && self.recent_terminal_block_for_block_hash(&terminal_block.block_hash()).is_none() {
                // the newly chain locked block is not in the main chain, we will need to reorg to it
                println!("Added a chain lock for block {:?} that was not on the main terminal chain ending in {:?}, reorginizing", terminal_block, self.last_sync_block());
                // clb chain locked block
                // tbmc terminal block
                let mut clb: Option<&dyn IBlock> = Some(terminal_block.clone());
                let mut tbmc = self.last_terminal_block();
                let mut cancel_reorg = false;
                while clb.is_some() && tbmc.is_some() && clb.unwrap().block_hash() != tbmc.unwrap().block_hash() {
                    // walk back to where the fork joins the main chain
                    if tbmc.unwrap().chain_locked() {
                        // if a block is already chain locked then do not reorg
                        cancel_reorg = true;
                    }
                    if clb.unwrap().height() < tbmc.unwrap().height() {
                        tbmc = self.terminal_blocks.get(&tbmc.unwrap().prev_block()).copied();
                    } else if clb.unwrap().height() > tbmc.unwrap().height() {
                        clb = self.terminal_blocks.get(&clb.unwrap().prev_block()).copied();
                    } else {
                        tbmc = self.terminal_blocks.get(&tbmc.unwrap().prev_block()).copied();
                        clb = self.terminal_blocks.get(&clb.unwrap().prev_block()).copied();
                    }
                }
                if cancel_reorg {
                    println!("Cancelling terminal reorg because block {:?} is already chain locked", tbmc.unwrap());
                } else {
                    println!("Reorginizing to height {:?}", clb.unwrap().height());
                    self.last_terminal_block = Some(terminal_block.clone());
                    let fork_chains_terminal_blocks = self.fork_chains_terminal_blocks();
                    let mut added_blocks = Vec::<UInt256>::new();
                    let mut done = false;
                    while !done {
                        let mut found = false;
                        for (block_hash, _) in fork_chains_terminal_blocks {
                            if added_blocks.contains(&block_hash) {
                                continue;
                            }
                            if let Some(potential_next_terminal_block) = self.terminal_blocks.get_mut(&block_hash) {
                                if potential_next_terminal_block.prev_block() == self.last_terminal_block().unwrap().block_hash() {
                                    self.add_block(potential_next_terminal_block, true, None);
                                    added_blocks.push(block_hash);
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if !found {
                            done = true;
                        }
                    }
                }
            }
        }
        let sync_block_opt = self.sync_blocks.get(&chain_lock.block_hash);
        if let Some(mut sync_block) = sync_block_opt {
            sync_block.set_chain_locked_with_chain_lock(chain_lock);
            let mut sbmc = self.last_sync_block_dont_use_checkpoints();
            if sbmc.is_some() && sync_block.chain_locked() && self.recent_sync_block_for_block_hash(&sync_block.block_hash()).is_none() {
                // the newly chain locked block is not in the main chain, we will need to reorg to it
                println!("Added a chain lock for block {:?} that was not on the main sync chain ending in {:?}, reorginizing", sync_block, self.last_sync_block());
                // clb chain locked block
                // sbmc sync block main chain
                let mut clb: Option<&dyn IBlock> = Some(sync_block.clone());
                let mut cancel_reorg = false;
                while clb.is_some() && sbmc.is_some() && clb.unwrap().block_hash() != sbmc.unwrap().block_hash() {
                    // walk back to where the fork joins the main chain
                    if sbmc.unwrap().chain_locked() {
                        // if a block is already chain locked then do not reorg
                        cancel_reorg = true;
                    } else if clb.unwrap().height() < sbmc.unwrap().height() {
                        sbmc = self.sync_blocks.get(&sbmc.unwrap().prev_block()).copied();
                    } else if clb.unwrap().height() > sbmc.unwrap().height() {
                        clb = self.sync_blocks.get(&clb.unwrap().prev_block()).copied();
                    } else {
                        sbmc = self.sync_blocks.get(&sbmc.unwrap().prev_block()).copied();
                        clb = self.sync_blocks.get(&clb.unwrap().prev_block()).copied();
                    }
                }
                if cancel_reorg {
                    println!("Cancelling sync reorg because block {:?} is already chain locked", sbmc);
                } else {
                    self.last_sync_block = Some(sync_block).copied();
                    println!("Reorginizing to height {} (last sync block {:?})", clb.unwrap().height(), self.last_sync_block());
                    let mut tx_hashes = Vec::<UInt256>::new();
                    // mark transactions after the join point as unconfirmed
                    for wallet in self.wallets {
                        for tx in wallet.all_transactions() {
                            if tx.block_height() <= clb.unwrap().height() {
                                break;
                            }
                            tx_hashes.push(tx.tx_hash());
                        }
                    }
                    self.set_block_height(TX_UNCONFIRMED as u32, 0, tx_hashes);
                    clb = Some(sync_block).copied();
                    while clb.is_some() && clb.unwrap().height() > sbmc.unwrap().height() {
                        // set transaction heights for new main chain
                        let prev_block = self.sync_blocks.get(&clb.unwrap().prev_block());
                        let tx_time = clb.unwrap().timestamp() + if prev_block.is_some() { prev_block.unwrap().timestamp() } else { 0 };
                        self.set_block_height(clb.unwrap().height(), tx_time as u64, clb.unwrap().transaction_hashes());
                        clb = prev_block.copied();
                    }
                    let fork_chains_terminal_blocks = self.fork_chains_sync_blocks();
                    let mut added_blocks = Vec::<UInt256>::new();
                    let mut done = false;
                    while !done {
                        let mut found = false;
                        for (block_hash, _) in fork_chains_terminal_blocks {
                            if added_blocks.contains(&block_hash) {
                                continue;
                            }
                            if let Some(potential_next_terminal_block) = self.sync_blocks.get_mut(&block_hash) {
                                if potential_next_terminal_block.prev_block() == self.last_sync_block().unwrap().block_hash() {
                                    self.add_block(potential_next_terminal_block, false, None);
                                    added_blocks.push(block_hash);
                                    found = true;
                                    break;
                                }
                            }
                        }
                        if !found {
                            done = true;
                        }
                    }
                }
            }
        }
        (terminal_block_opt.is_some() && terminal_block_opt.unwrap().chain_locked()) ||
            (sync_block_opt.is_some() && sync_block_opt.unwrap().chain_locked())
    }

    pub fn block_height_chain_locked(&mut self, height: u32) -> bool {
        let mut b = self.last_terminal_block();
        let mut confirmed = false;
        while b.is_some() && b.unwrap().height() > height {
            b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
            confirmed |= b.is_some() && b.unwrap().chain_locked();
        }
        b.is_some() && b.unwrap().height() == height && confirmed
    }

    /// Heights
    pub fn last_sync_block_timestamp(&mut self) -> u32 {
        if let Some(last) = &self.last_sync_block {
            last.timestamp()
        } else if self.last_persisted_chain_info.block_timestamp != 0 {
            self.last_persisted_chain_info.block_timestamp as u32
        } else {
            self.last_sync_block().unwrap().timestamp()
        }
    }

    pub fn last_sync_block_height(&mut self) -> u32 {
        if let Some(last) = &self.last_sync_block {
            last.height()
        } else if self.last_persisted_chain_info.block_height != 0 {
            self.last_persisted_chain_info.block_height
        } else {
            self.last_sync_block().unwrap().height()
        }
    }

    pub fn last_sync_block_hash(&mut self) -> UInt256 {
        if let Some(last) = &self.last_sync_block {
            last.block_hash()
        } else if !self.last_persisted_chain_info.block_hash.is_zero() {
            self.last_persisted_chain_info.block_hash.clone()
        } else {
            self.last_sync_block().unwrap().block_hash()
        }
    }
    // pub fn last_sync_block_hash(&self) -> Option<UInt256> {
    //     if let Some(last) = &self.last_sync_block {
    //         Some(last.block_hash())
    //     } else if !self.last_persisted_chain_info.block_hash.is_zero() {
    //         Some(self.last_persisted_chain_info.block_hash.clone())
    //     } else {
    //         self.last_sync_block().block_hash()
    //     }
    // }

    pub fn last_sync_block_chain_work(&mut self) -> UInt256 {
        if let Some(last) = &self.last_sync_block {
            last.chain_work()
        } else if !self.last_persisted_chain_info.block_hash.is_zero() {
            self.last_persisted_chain_info.block_hash.clone()
        } else {
            self.last_sync_block().unwrap().chain_work()
        }
    }

    pub fn last_terminal_block_height(&mut self) -> u32 {
        self.last_terminal_block().unwrap().height()
    }

    pub fn quick_height_for_block_hash(&self, block_hash: UInt256) -> u32 {
        if let Some(checkpoint) = self.checkpoints_by_hash_dictionary.get(&block_hash) {
            return checkpoint.height;
        }
        if let Some(sync_block) = self.sync_blocks.get(&block_hash) {
            if sync_block.height() != u32::MAX {
                return sync_block.height();
            }
        }
        if let Some(terminal_block) = self.terminal_blocks.get(&block_hash) {
            if terminal_block.height() != u32::MAX {
                return terminal_block.height();
            }
        }
        if let Some(checkpoint) = self.checkpoints.iter().find(|checkpoint| checkpoint.hash == block_hash) {
            return checkpoint.height;
        }
        u32::MAX
    }

    pub fn height_for_block_hash(&mut self, block_hash: &UInt256) -> u32 {
        if let Some(checkpoint) = self.checkpoints_by_hash_dictionary.get(block_hash) {
            return checkpoint.height;
        }
        if let Some(sync_block) = self.sync_blocks.get(block_hash) {
            if sync_block.height() != u32::MAX {
                return sync_block.height();
            }
        }
        if let Some(terminal_block) = self.terminal_blocks.get(block_hash) {
            if terminal_block.height() != u32::MAX {
                return terminal_block.height();
            }
        }
        let mut b = self.last_terminal_block();
        if b.is_none() {
            b = self.last_sync_block();
        }
        while b.is_some() && b.unwrap().height() > 0 {
            if b.unwrap().block_hash() == *block_hash {
                return b.unwrap().height();
            }
            b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
            if b.is_none() {
                b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
            }
        }
        if let Some(checkpoint) = self.checkpoints.iter().find(|checkpoint| checkpoint.hash == *block_hash) {
            return checkpoint.height;
        }
        if self.params.allow_insight_blocks_for_verification() {
            if let Some(insight_block) = self.insight_verified_blocks_by_hash_dictionary.get(block_hash) {
                return insight_block.height();
            }
        }
        u32::MAX
    }

    // seconds since reference date, 00:00:00 01/01/01 GMT
    // NOTE: this is only accurate for the last two weeks worth of blocks, other timestamps are estimated from checkpoints
    pub fn timestamp_for_block_height(&mut self, block_height: u32) -> u32 {
        if block_height == TX_UNCONFIRMED as u32 {
            if let Some(block) = self.last_terminal_block() {
                return block.timestamp() + 150; // next block
            }
        }
        if block_height >= self.last_terminal_block_height() {
            // future block, assume 2.5 minutes per block after last block
            if let Some(block) = self.last_terminal_block() {
                return block.timestamp() + (block_height - self.last_terminal_block_height() * 150);
            }
        }
        if !self.terminal_blocks.is_empty() {
            if block_height >= self.last_terminal_block_height() - DGW_PAST_BLOCKS_MAX as u32 {
                // recent block we have the header for
                let mut block = self.last_terminal_block().clone();
                while block.is_some() && block.unwrap().height() > block_height {
                    block = self.terminal_blocks.get(&block.unwrap().prev_block()).copied();
                }
                if let Some(block) = block {
                    return block.timestamp();
                }
            }
        } else {
            // load blocks
            let _ = self.terminal_blocks();
        }
        let mut h = self.last_sync_block_height();
        let mut t = self.last_sync_block().unwrap().timestamp();
        for i in (0..self.checkpoints.len()).rev() {
            if let Some(checkpoint) = self.checkpoints.get(i) {
                if checkpoint.height <= block_height {
                    if h == checkpoint.height {
                        return t;
                    }
                    t = checkpoint.timestamp + (t - checkpoint.timestamp) * (block_height - checkpoint.height) / (h - checkpoint.height);
                    return t;
                }
                h = checkpoint.height;
                t = checkpoint.timestamp;
            }
        }
        self.checkpoints.first().unwrap().timestamp
    }

    pub fn set_block_height(&mut self, height: u32, timestamp: u64, transaction_hashes: Vec<UInt256>) {
        if height != TX_UNCONFIRMED as u32 && height > self.best_block_height {
            self.best_block_height = height;
        }
        let mut updated_transaction_hashes = Vec::<UInt256>::new();
        if !transaction_hashes.is_empty() {
            // need to reverify this works
            transaction_hashes.iter().for_each(|&hash| {
                self.transaction_hash_heights.insert(hash, height);
                self.transaction_hash_timestamps.insert(hash, timestamp);
            });
            self.wallets.iter().for_each(|mut wallet| {
                updated_transaction_hashes.extend(wallet.set_block_height(height, timestamp, &transaction_hashes));
            });
        } else {
            self.wallets.iter().for_each(|mut wallet| {
                wallet.chain_updated_block_height(height);
            });
        }
        self.chain_did_set_block_height(height, timestamp, &transaction_hashes, &updated_transaction_hashes);
    }

    pub fn reload_derivation_paths(&self) {
        self.wallets.iter().for_each(|wallet| {
            // no need to reload transient wallets (those are for testing purposes)
            if !wallet.is_transient {
                wallet.reload_derivation_paths();
            }
        })
    }

    pub fn estimated_block_height(&mut self) -> u32 {
        if let Some(bebh) = self.best_estimated_block_height {
            bebh
        } else {
            let bebh = self.decide_from_peer_soft_consensus_estimated_block_height();
            self.best_estimated_block_height = Some(bebh);
            bebh
        }
    }

    pub fn decide_from_peer_soft_consensus_estimated_block_height(&self) -> u32 {
        let mut max_count = 0u32;
        let mut temp_best_estimated_block_height = 0u32;
        for (height, announcers) in self.estimated_block_heights {
            let announcers_count = announcers.len() as u32;
            if announcers_count > max_count {
                temp_best_estimated_block_height = height;
                max_count = announcers_count;
            } else if announcers_count == max_count && temp_best_estimated_block_height < height {
                // use the latest if deadlocked
                temp_best_estimated_block_height = height;
            }
        }
        temp_best_estimated_block_height
    }

    pub fn count_estimated_block_height_announcers(&self) -> usize {
        self.estimated_block_heights.iter().fold(Vec::new(), |mut announcers, announcers_at_height| {
            announcers.extend(announcers_at_height.1);
            announcers
        }).len()
    }

    pub fn set_estimated_block_height(&mut self, estimated_block_height: u32, peer: &Peer, threshold_peer_count: usize) {
        let old_estimated_block_height = self.estimated_block_height();
        // remove from other heights
        for (height, mut announcers) in self.estimated_block_heights {
            if height == estimated_block_height {
                continue;
            }
            if let Some(pos) = announcers.iter().position(|x| x == peer) {
                announcers.remove(pos);
            }
            if announcers.is_empty() {
                self.estimated_block_heights.remove_entry(&height);
            }
        }

        if let Some(mut peers_announcing_height) = self.estimated_block_heights.get_mut(&estimated_block_height) {
            if !peers_announcing_height.contains(peer) {
                peers_announcing_height.push((*peer).clone());
            }
        } else {
            self.estimated_block_heights.insert(estimated_block_height, vec![*peer]);
        }
        if self.count_estimated_block_height_announcers() > threshold_peer_count {
            let final_estimated_block_height = self.decide_from_peer_soft_consensus_estimated_block_height();
            if final_estimated_block_height > old_estimated_block_height {
                self.best_estimated_block_height = Some(final_estimated_block_height);
                //once_with(|| {
                    self.assign_sync_weights();
                //});
                todo!()
                // dispatch_once(&onceToken, ^{
                //     [self.chainManager assignSyncWeights];
                // });
                // dispatch_async(dispatch_get_main_queue(), ^{
                //     [[NSNotificationCenter defaultCenter] postNotificationName:DSChainManagerSyncParametersUpdatedNotification object:nil userInfo:@{DSChainManagerNotificationChainKey: self}];
                // });
            } else {
                // dispatch_once(&onceToken, ^{
                //     [self.chainManager assignSyncWeights];
                // });
            }
        }
    }

    pub fn remove_estimated_block_heights_of_peer(&mut self, peer: &Peer) {
        for (height, mut announcers) in self.estimated_block_heights {
            if let Some(pos) = announcers.iter().position(|x| x == peer) {
                announcers.remove(pos);
            }
            if announcers.is_empty() {
                self.estimated_block_heights.remove_entry(&height);
            }
            // keep best estimate if no other peers reporting on estimate
            if !self.estimated_block_heights.is_empty() && height == self.best_estimated_block_height.unwrap() {
                self.best_estimated_block_height = Some(0);
            }
        }
    }


    /// Wiping

    pub fn wipe_blockchain_info(&mut self, context: &ManagedContext) {
        println!("Wiping Blockchain Info");
        self.wallets.iter().for_each(|mut wallet| wallet.wipe_blockchain_info(context));
        self.wipe_identities_persisted_data(context);
        self.wipe_blockchain_invitations_persisted_data_in_context(context);
        self.identities_manager().clear_external_blockchain_identities();
        self.best_block_height = 0;
        self.sync_blocks.clear();
        self.terminal_blocks.clear();
        self.last_sync_block = None;
        self.last_terminal_block = None;
        self.last_persisted_chain_info = LastPersistedChainInfo::default();
        self.set_last_terminal_block_from_checkpoints();
        self.set_last_sync_block_from_checkpoints();
        self.transaction_manager().chain_was_wiped();
    }

    pub fn wipe_blockchain_non_terminal_info(&mut self, context: &ManagedContext) {
        println!("Wiping Blockchain Non Terminal Info");
        self.wallets.iter().for_each(|mut wallet| wallet.wipe_blockchain_info(context));
        self.wipe_identities_persisted_data(context);
        self.wipe_blockchain_invitations_persisted_data_in_context(context);
        self.viewing_account().wipe_blockchain_info();
        self.best_block_height = 0;
        self.sync_blocks.clear();
        self.last_sync_block = None;
        self.last_persisted_chain_info = LastPersistedChainInfo::default();
        self.set_last_sync_block_from_checkpoints();
        self.transaction_manager().chain_was_wiped();

    }

    /*pub fn wipe_masternodes_in_context(&mut self, context: &ManagedContext) {
        println!("Wiping Masternode Info");
        // TODO: No need to implement

        // DSChainEntity *chainEntity = [self chainEntityInContext:context];
        // [DSLocalMasternodeEntity deleteAllOnChainEntity:chainEntity];
        // [DSSimplifiedMasternodeEntryEntity deleteAllOnChainEntity:chainEntity];
        // [DSQuorumEntryEntity deleteAllOnChainEntity:chainEntity];
        // [DSMasternodeListEntity deleteAllOnChainEntity:chainEntity];
        // [DSQuorumSnapshotEntity deleteAllOnChainEntity:chainEntity];
        self.wipe_masternode_info();
        let key = format!("{}_{}", self.unique_id, LAST_SYNCED_MASTERNODE_LIST);
        UserDefaults::remove_object_for_key(&key);
    }*/

    pub fn wipe_wallets_and_derivatives(&mut self) {
        println!("Wiping Wallets and Derivatives");
        self.unregister_all_wallets();
        self.unregister_all_standalone_derivation_paths();
        self.viewing_account = None;
    }

    pub(crate) fn wipe_masternode_info(&self) {
        self.masternode_manager().wipe_local_masternode_info();
        self.masternode_manager().wipe_masternode_info();
    }


    // pub fn init_as_devnet_with_type(r#type: DevnetType, version: u16, protocol_version: u32, checkpoints: Option<Vec<Checkpoint>>) -> Self {
    //     // for devnet the genesis checkpoint is really the second block
    //     let mut chain = Chain::new(create_devnet_params_for_type(r#type));
    //     if checkpoints.is_none() || checkpoints.unwrap().is_empty() {
    //         let genesis_checkpoint = Checkpoint::genesis_devnet_checkpoint();
    //         let second_checkpoint = Checkpoint::create_dev_net_genesis_block_checkpoint_for_parent_checkpoint(genesis_checkpoint, r#type, version, protocol_version);
    //         chain.checkpoints = vec![genesis_checkpoint, second_checkpoint];
    //         //self.genesisHash = secondCheckpoint.blockHash;
    //     } else {
    //         chain.checkpoints = checkpoints.unwrap();
    //         //self.genesisHash = checkpoints[1].blockHash;
    //     }
    //     // dispatch_sync(self.networkingQueue, ^{
    //     //     self.chainManagedObjectContext = [NSManagedObjectContext chainContext];
    //     // });
    //     //    DSLog(@"%@",[NSData dataWithUInt256:self.checkpoints[0].checkpointHash]);
    //     //    DSLog(@"%@",[NSData dataWithUInt256:self.genesisHash]);
    //     // self.devnetIdentifier = identifier;
    //     // self.headers_max_amount = DEVNET_DEFAULT_HEADERS_MAX_AMOUNT;
    //     chain
    // }



    pub fn setup(&mut self) {
        self.retrieve_wallets();
        self.retrieve_standalone_derivation_paths();
    }

    pub fn fork_chains_sync_blocks(&self) -> HashMap<UInt256, &dyn IBlock> {
        let mut fcsb = self.sync_blocks.clone();
        let mut b = self.last_sync_block.clone();
        while b.is_some() && b.unwrap().height() > 0 {
            b = self.sync_blocks.get(&b.unwrap().prev_block()).copied();
            fcsb.remove(&b.unwrap().block_hash());
        }
        fcsb
    }

    pub fn fork_chains_terminal_blocks(&self) -> HashMap<UInt256, &dyn IBlock> {
        let mut fctb = self.terminal_blocks.clone();
        let mut b = self.last_terminal_block.clone();
        while b.is_some() && b.unwrap().height() > 0 {
            b = self.terminal_blocks.get(&b.unwrap().prev_block()).copied();
            fctb.remove(&b.unwrap().block_hash());
        }
        fctb
    }


    pub fn platform(&mut self) -> &Platform {
        self.platform.unwrap_or_else(|| {
            let pf = Platform::new(self);
            self.platform = Some(&pf);
            &pf
        })
    }


    pub fn new(params: Params,
               checkpoints: Vec<Checkpoint>,
               authentication_manager: &AuthenticationManager,
               environment: &Environment,
               network_context: NetworkContext,
               store_context: StoreContext) -> Self {
        //NSAssert([NSThread isMainThread], @"Chains should only be created on main thread (for chain entity optimizations)");

        let fee_per_byte = if let Some(saved_fee) = UserDefaults::double_for_key(FEE_PER_BYTE_KEY) {
            if saved_fee >= MIN_FEE_PER_B && saved_fee <= MAX_FEE_PER_B {
                saved_fee
            } else {
                DEFAULT_FEE_PER_B
            }
        } else {
            DEFAULT_FEE_PER_B
        };

        let mut chain = Self {
            network_context,
            store_context,
            authentication_manager,
            environment,
            platform: None,
            fee_per_byte,
            is_transient: false,
            unique_id: short_hex_string_from(&params.chain_type.genesis_hash().0),
            params,
            checkpoints,
            options: Options::default(),
            derivation_path_factory: Default::default(),
            last_persisted_chain_info: Default::default(),
            ..Default::default()
        };

        chain.spork_manager = Some(spork::Manager { chain: &chain, ..Default::default() });
        chain.masternode_manager = Some(MasternodeManager::new(&chain));
        chain.peer_manager = Some(PeerManager { chain: &chain, ..Default::default() });
        chain.transaction_manager = Some(TransactionManager { chain: &chain, ..Default::default() });
        chain.governance_sync_manager = Some(GovernanceSyncManager { chain: &chain, ..Default::default() });
        chain.identities_manager = Some(IdentitiesManager { chain: &chain, ..Default::default() });
        chain.dapi_client = Some(dapi::Client { chain: &chain, ..Default::default() });
        chain
    }



    pub fn user_agent(&self) -> String {
        self.r#type().user_agent()
    }

    pub fn chain_synchronization_block_zones(&mut self) -> HashSet<u16> {
        if self.chain_synchronization_block_zones.is_none() {
            let zones = Wallet::block_zones_from_chain_synchronization_fingerprint(self.chain_synchronization_fingerprint.clone().unwrap(), 0, 0);
            self.chain_synchronization_block_zones = Some(zones);
        }
        self.chain_synchronization_block_zones.unwrap()
    }

    pub fn should_request_merkle_blocks_for_zone_between_height(&mut self, block_height: u32, end_block_height: u32) -> bool {
        let block_zone = (block_height / 500) as u16;
        let end_block_zone = (end_block_height / 500 + (if end_block_height % 500 != 0 { 1 } else { 0 })) as u16;
        if let Some(fingerprint) = &self.chain_synchronization_fingerprint {
            while block_zone < end_block_zone {
                if self.chain_synchronization_block_zones().contains(&block_zone) {
                    return true;
                }
            }
           false
        } else {
            true
        }
    }


    pub fn should_request_merkle_blocks_for_zone_after_height(&mut self, block_height: u32) -> bool {
        let block_zone: u16 = (block_height / 500) as u16;
        let left_over: u16 = (block_height % 500) as u16;
        if self.chain_synchronization_fingerprint.is_some() {
            self.chain_synchronization_block_zones().contains(&block_zone) ||
                self.chain_synchronization_block_zones().contains(&(block_zone + 1)) ||
                self.chain_synchronization_block_zones().contains(&(block_zone + 2)) ||
                self.chain_synchronization_block_zones().contains(&(block_zone + 3)) ||
                (left_over == 0 && self.should_request_merkle_blocks_for_zone_after_height(((block_zone + 1) * 500) as u32))
        } else {
            true
        }
    }


    pub fn dapi_client(&self) -> &dapi::Client {
        &self.dapi_client.unwrap()
    }
}
