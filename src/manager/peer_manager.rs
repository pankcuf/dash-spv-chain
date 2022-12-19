use rand::thread_rng;
use std::cmp::{min, Ordering};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::chain::common::ChainType;
use crate::consensus::Encodable;
use crate::crypto::{UInt128, UInt256};
use crate::crypto::byte_util::Zeroable;
use crate::models::MasternodeList;
use secp256k1::rand;
use secp256k1::rand::Rng;
use crate::chain::chain::Chain;
use crate::chain::dispatch_context::DispatchContext;
use crate::chain::extension::sync_progress::SyncProgress;
use crate::chain::options::sync_type::SyncType;
use crate::chain::spork;
use crate::keychain::keychain::Keychain;
use crate::manager::governance_sync_manager::GovernanceSyncManager;
use crate::manager::peer_manager_desired_state::PeerManagerDesiredState;
use crate::manager::transaction_manager::TransactionManager;
use crate::chain::masternode::MasternodeManager;
use crate::chain::network::bloom_filter::BloomFilter;
use crate::chain::network::message::inv_type::InvType;
use crate::chain::network::peer::{DAYS_3_TIME_INTERVAL, HOURS_3_TIME_INTERVAL, MempoolTransactionCallback, Peer};
use crate::chain::network::peer_status::PeerStatus;
use crate::chain::network::peer_type::PeerType;
use crate::manager::masternode_manager::MasternodeManager;
use crate::notifications::{Notification, NotificationCenter};
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::common::peer::PeerEntity;
use crate::storage::models::entity::Entity;
use crate::user_defaults::UserDefaults;
use crate::util::time::TimeUtil;
use crate::util::TimeUtil;

pub const PEER_MAX_CONNECTIONS: usize = 5;
pub const SETTINGS_FIXED_PEER_KEY: &str = "SETTINGS_FIXED_PEER";
pub const LAST_SYNCED_GOVERANCE_OBJECTS: &str = "LAST_SYNCED_GOVERANCE_OBJECTS";
pub const LAST_SYNCED_MASTERNODE_LIST: &str = "LAST_SYNCED_MASTERNODE_LIST";

const MAINNET_DNS_SEEDS: Vec<&str> = vec!["dnsseed.dash.org"];
const TESTNET_DNS_SEEDS: Vec<&str> = vec!["testnet-seed.dashdot.io"];

/// services value indicating a node carries full blocks, not just headers
pub const SERVICES_NODE_NETWORK: u64 = 0x01;
/// BIP111: https://github.com/bitcoin/bips/blob/master/bip-0111.mediawiki
pub const SERVICES_NODE_BLOOM: u64 = 0x04;
/// notify user of network problems after this many connect failures in a row
pub const MAX_CONNECT_FAILURES: u32 = 20;

pub struct PeerInfo {
    pub address: UInt128,
    pub port: u16,
    pub dapi_jrpc_port: u32,
    pub dapi_grpc_port: u32,
}

pub enum Error {
    ServiceNetworkError(Peer),
    BloomFilteringNotSupported(Peer),
    NoPeersFound,
    SyncTimeout,
    Default(String),
}

impl Error {
    pub fn is_app_level(&self) -> bool {
        true
    }
    pub fn code(&self) -> i32 {
        match self {
            Error::NoPeersFound => 1,
            _ => 500
        }
    }

    pub fn message(&self) -> String {
        match self {
            Error::ServiceNetworkError(peer) => format!("Node at host {} does not service network", peer.host()),
            Error::BloomFilteringNotSupported(peer) => format!("Node at host {} does not support bloom filtering", peer.host()),
            Error::NoPeersFound => format!("No peers found"),
            Error::SyncTimeout => format!("An error message for notifying that chain sync has timed out"),
            Error::Default(message) => message
        }
    }
}

pub struct PeerManager {
    pub(crate) chain: &'static Chain,
    peers: Vec<Peer>,
    mutable_connected_peers: HashSet<Peer>,
    mutable_misbehaving_peers: HashSet<Peer>,
    pub(crate) download_peer: Option<Peer>,
    fixed_peer: Option<Peer>,

    connect_failures: u32,
    max_connect_count: usize,
    connected_peers: HashSet<Peer>,
    desired_state: PeerManagerDesiredState,
    masternode_list: Option<&'static MasternodeList>,
    masternode_list_connectivity_nonce: u64,
    pub(crate) connected: bool,

    context: &'static ManagedContext,
    // @property (nonatomic, readonly) NSUInteger connectFailures, misbehavingCount, maxConnectCount;

}

impl PeerManager {
    pub fn new(chain: &Chain) -> Self {
        Self {
            chain,
            // todo: init peer_context in networking queue
            context: chain.peer_context(),
            max_connect_count: PEER_MAX_CONNECTIONS,
            ..Default::default()
        }
    }

    /// Managers
    pub fn masternode_manager(&self) -> &MasternodeManager {
        self.chain.masternode_manager()
    }

    pub fn transaction_manager(&self) -> &TransactionManager {
        self.chain.transaction_manager()
    }

    pub fn governance_sync_manager(&self) -> &GovernanceSyncManager {
        self.chain.governance_sync_manager()
    }

    pub fn spork_manager(&self) -> &spork::Manager {
        self.chain.spork_manager()
    }

    /// number of connected peers
    pub fn connected_peer_count(&self) -> usize {
        self.connected_peers.iter().filter(|peer| peer.status() == PeerStatus::Connected).count()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn download_peer_name(&self) -> String {
        if let Some(peer) = &self.download_peer {
            format!("{}:{}", peer.host(), peer.port)
        } else {
            ""
        }
    }

    fn dns_seeds(&self) -> Vec<&str> {
        match self.chain.params.chain_type {
            ChainType::MainNet => MAINNET_DNS_SEEDS,
            ChainType::TestNet => TESTNET_DNS_SEEDS,
            ChainType::DevNet(_) => vec![]
        }
    }

    /// Peers
    pub fn remove_trusted_peer_host(&mut self) {
        self.disconnect();
        self.set_trusted_peer_host(None);
    }

    pub fn clear_peers(&mut self) {
        self.disconnect();
        self.peers.clear();
    }

    pub fn peers(&mut self) -> Vec<Peer> {
        if let Some(&fixed) = &self.fixed_peer {
            return vec![fixed];
        }
        if self.peers.len() >= self.max_connect_count {
            return self.peers.clone();
        }
        self.peers = vec![];
        self.context.perform_block_and_wait(|context| {
            match PeerEntity::get_all_peers_for_chain(self.chain.r#type(), context) {
                Ok(peers) => {
                    peers.iter().for_each(|peer| {
                        if peer.misbehaving == 0 {
                            self.peers.push(peer.peer(self.chain));
                        } else {
                            self.mutable_misbehaving_peers.insert(peer.peer(self.chain));
                        }
                    });
                },
                Err(err) => println!("Error retrieving peers")
            }
        });
        self.sort_peers();
        if self.chain.is_devnet_any() {
            self.peers.extend(self.registered_devnet_peers());
            if let Some(masternode_list) = &self.masternode_list {
                self.peers.extend(masternode_list.peers_with_connectivity_nonce(8, self.masternode_list_connectivity_nonce));
            }
            self.sort_peers();
            return self.peers.clone();
        }
        if let Some(masternode_list) = &self.masternode_list {
            self.peers.extend(masternode_list.peers_with_connectivity_nonce(500, self.masternode_list_connectivity_nonce));
            self.sort_peers();
            return self.peers.clone();
        }

        // DNS peer discovery
        let now = SystemTime::seconds_since_1970();
        let mut peers = Vec::<Vec<Peer>>::new();
        let dns_seeds = self.dns_seeds();
        if self.peers.len() < PEER_MAX_CONNECTIONS || self.peers.get(PEER_MAX_CONNECTIONS - 1).unwrap().timestamp + DAYS_3_TIME_INTERVAL < now {
            while peers.len() < dns_seeds.len() {
                peers.push(vec![]);
            }
        }
        self.peers.clone()
    }

    pub fn sort_peers(&mut self) {
        let three_hours_ago = SystemTime::seconds_since_1970() - HOURS_3_TIME_INTERVAL;
        let syncs_masternode_list = &self.chain.options.sync_type & SyncType::MasternodeList != 0;
        let syncs_governance_objects = &self.chain.options.sync_type & SyncType::Governance != 0;
        self.peers.sort_by(|&p1, &p2| {
            // the following is to make sure we get
            if syncs_masternode_list {
                if (p1.last_requested_masternode_list.is_none() || p1.last_requested_masternode_list.unwrap() < three_hours_ago) &&
                    p2.last_requested_masternode_list.unwrap() > three_hours_ago {
                    return Ordering::Less; // NSOrderedDescending
                }
                if p1.last_requested_masternode_list.unwrap() > three_hours_ago &&
                    (p2.last_requested_masternode_list.is_none() || p2.last_requested_masternode_list.unwrap() < three_hours_ago) {
                    return Ordering::Greater; // NSOrderedAscending
                }
            }
            if syncs_governance_objects {
                if (p1.last_requested_governance_sync.is_none() || p1.last_requested_governance_sync.unwrap() < three_hours_ago) &&
                    p2.last_requested_governance_sync.unwrap() > three_hours_ago {
                    return Ordering::Less; // NSOrderedDescending
                }
                if p1.last_requested_governance_sync.unwrap() > three_hours_ago &&
                    (p2.last_requested_governance_sync.is_none() || p2.last_requested_governance_sync.unwrap() < three_hours_ago) {
                    return Ordering::Greater; // NSOrderedAscending
                }
                if p1.priority > p2.priority {
                    return Ordering::Greater; // NSOrderedAscending
                }
                if p1.priority < p2.priority {
                    return Ordering::Less; // NSOrderedDescending
                }
                if p1.timestamp > p2.timestamp {
                    return Ordering::Greater; // NSOrderedAscending
                }
                if p1.timestamp < p2.timestamp {
                    return Ordering::Less; // NSOrderedDescending
                }
            }
            Ordering::Equal
        });
    }

    pub fn save_peers(&self) {
        println!("[PeerManager] save peers");
        let mut peers = HashSet::from_iter(self.peers.iter().cloned().chain(self.mutable_misbehaving_peers.iter()));
        let addrs = peers.iter().filter_map(|peer| {
            //usize::from_le_bytes(<[u8; 8]>::try_from(b)?) > v
            if peer.address.0[0] != 0 /*|| peer.address.0[2 * 4] != b'0xffff'.to_be()*/ {
                None
            } else {
                peer.address.ip_address_to_i32()
            }
        }).collect();

        self.context.perform_block(|context| {
            ChainEntity::get_chain(self.chain.r#type(), context)
                .and_then(|chain_entity| PeerEntity::delete_peers_except_list(self.chain.r#type(), addrs, context)
                    .and_then(|deleted| PeerEntity::get_peers_with_addresses_for_chain(&chain_entity, addrs, context)
                        .and_then(|peer_entities| {
                            peer_entities.iter().for_each(|peer_entity| {
                                let peer = peer_entity.peer(self.chain);
                                if let Some(p) = peers.get(&peer) {
                                    match peer_entity.update_with_peer(p, context) {
                                        Ok(updated) => {
                                            peers.remove(p);
                                        },
                                        Err(err) => println!("Sqlite Error  {:?}", err)
                                    }
                                } else {
                                    match peer_entity.delete_itself(context) {
                                        Ok(deleted) => {},
                                        Err(err) => println!("Sqlite Error  {:?}", err)
                                    }
                                }
                            });
                            PeerEntity::create_from_peers(peers, chain_entity.id, context)
                        }))).expect("Can't update peers");
        });
    }

    pub fn peer_for_location(&self, ip_address: UInt128, port: u16) -> Option<&Peer> {
        self.peers.iter().find(|peer| peer.address == ip_address && peer.port == port)
    }

    pub fn status_for_location(&self, ip_address: UInt128, port: u16) -> PeerStatus {
        match self.peer_for_location(ip_address, port) {
            None => PeerStatus::Unknown,
            Some(peer) => if self.mutable_misbehaving_peers.contains(peer) { PeerStatus::Banned } else { &peer.status }
        }
    }

    pub fn type_for_location(&self, ip_address: UInt128, port: u16) -> PeerType {
        match self.peer_for_location(ip_address, port) {
            None => PeerType::Unknown,
            Some(_) => if self.masternode_manager().has_masternode_at_location(ip_address, port) { PeerType::MasterNode } else { PeerType::FullNode }
        }
    }

    pub fn settings_fixed_peer_key(&self) -> String {
        format!("{}_{}", SETTINGS_FIXED_PEER_KEY, self.chain.unique_id)
    }

    pub fn trusted_peer_host(&self) -> Option<&str> {
        if let Some(_object) = UserDefaults::object_for_key(&self.settings_fixed_peer_key()) {
            UserDefaults::string_for_key(&self.settings_fixed_peer_key())
        } else {
            None
        }
    }

    pub fn set_trusted_peer_host(&self, host: Option<String>) {
        if let Some(host) = host {
            UserDefaults::set_object_for_key(&self.settings_fixed_peer_key(), host)
        } else {
            UserDefaults::remove_object_for_key(&self.settings_fixed_peer_key())
        }
    }

    /// Peer Registration
    pub fn pause_blockchain_synchronization_on_peers(&mut self) {
        if let Some(peer) = &mut self.download_peer {
            peer.needs_filter_update = true;
        }
    }

    pub fn resume_blockchain_synchronization_on_peers(&mut self) {
        if let Some(peer) = &self.download_peer {
            peer.need_filter_update = false;
            self.update_filters_on_peers();
        } else {
            self.connect();
        }
    }


    pub fn update_filter_on_peers(&mut self) {
        if let Some(download_peer) = &mut self.download_peer {
            if download_peer.needs_filter_update {
                return;
            }
            download_peer.needs_filter_update = true;
            println!("filter update needed, waiting for pong");
            download_peer.send_ping_message(|success| {
                // wait for pong so we include already sent tx
                if !success { return; }
                // we are on chainPeerManagerQueue
                let tx_manager = self.transaction_manager();
                println!("updating filter with newly created wallet addresses");
                tx_manager.clear_transactions_bloom_filter();
                if self.chain.last_sync_block_height < self.chain.estimated_block_height() {
                    // if we're syncing, only update download peer
                    download_peer.send_filter_load_message(tx_manager.transactions_bloom_filter_for_peer(download_peer).data);
                    download_peer.send_ping_message(|success| {
                        // wait for pong so filter is loaded
                        if !success { return; }
                        download_peer.needs_filter_update = false;
                        download_peer.rerequest_blocks_from(&self.chain.last_sync_block.unwrap().block_hash());
                        download_peer.send_ping_message(|success| {
                            // wait for pong so filter is loaded
                            if !success || download_peer.needs_filter_update { return; }
                            download_peer.send_get_blocks_message_with_locators(self.chain.chain_sync_block_locator_array(), UInt256::MIN);
                        });
                    })
                } else {
                    self.connected_peers.iter_mut().for_each(|peer| {
                        if peer.status() == PeerStatus::Connected {
                            peer.send_filterload_message(self.transaction_manager().transactions_bloom_filter_for_peer(peer).data);
                            peer.send_ping_message(|success| {
                                // wait for pong so we know filter is loaded
                                if !success { return; }
                                peer.needs_filter_update = false;
                                peer.send_mempool_message(self.transaction_manager().published_tx.keys(), || {});
                            });
                        }
                    });
                }
            });
        }
    }


    /// Peer Registration


    pub fn clear_registered_peers(&mut self) {
        self.clear_peers();
        Keychain::set_array(vec![], self.chain.registered_peers_key(), false)
            .expect("Can't clear peers stored in keychain");
    }

    pub fn register_peer_at_location(&self, ip_address: UInt128, port: u16, dapi_jrpc_port: u32, dapi_grpc_port: u32) {
        let classes = vec!["String".to_string(), "Number".to_string(), "Dictionary".to_string(), "Data".to_string()];
        let mut registered_peer_infos = if let Ok(array) = Keychain::get_array::<PeerInfo>(self.chain.registered_peers_key(), classes) {
            array
        } else {
            vec![]
        };
        let insert_info = PeerInfo { address: ip_address, port, dapi_jrpc_port, dapi_grpc_port };
        if registered_peer_infos.iter().find(|info| info == insert_info).is_none() {
            registered_peer_infos.push(insert_info);
        }

        Keychain::set_array::<PeerInfo>(registered_peer_infos, self.chain.registered_peers_key(), false)
            .expect("Can't store peer infos in keychain");
    }

    pub fn registered_devnet_peers(&self) -> Vec<Peer> {
        let classes = vec!["String".to_string(), "Number".to_string(), "Dictionary".to_string(), "Data".to_string()];
        if let Ok(array) = Keychain::get_array::<PeerInfo>(self.chain.registered_peers_key(), classes) {
            let now = SystemTime::seconds_since_1970();
            let bound = 7 * 24 * 60 * 60;
            let random = bound + thread_rng().gen_range(0..bound);
            let timestamp = now - random;
            array.iter().map(|info| Peer::init_with_address(info.address, info.port, self.chain, timestamp, SERVICES_NODE_NETWORK | SERVICES_NODE_BLOOM)).collect()
        } else {
            vec![]
        }
    }

    pub fn peers_with_connectivity_nonce(&self, masternode_list: &MasternodeList, peer_count: usize, connectivity_nonce: u64) -> Vec<Peer> {
        let entries = &masternode_list.masternodes;
        let sorted_hashes = entries.keys().sorted_by(|&h1, &h2| {
            let mut h1v: Vec<u8> = Vec::new();
            h1.0.clone_into(&mut h1v);
            connectivity_nonce.enc(&mut h1v);
            let h1r = blake3::hash(&h1v).as_bytes();
            let h1ru = UInt256(*h1r);
            let mut h2v: Vec<u8> = Vec::new();
            h2.0.clone_into(&mut h2v);
            connectivity_nonce.enc(&mut h2v);
            let h2r = blake3::hash(&h2v).as_bytes();
            let h2ru = UInt256(*h2r);
            h1ru.cmp(&h2ru)
        });
        let mut result = Vec::<Peer>::new();
        (0..min(peer_count, entries.len())).into_iter().for_each(|i| {
            let hash = sorted_hashes[i];
            if let Some(masternode) = entries.get(hash) {
                if masternode.is_valid {
                    result.push(Peer::init_with_masternode(masternode, self.chain));
                }
            }
        });
        result
    }


    pub fn registered_devnet_peer_services(&self) -> Vec<String> {
        self.registered_devnet_peers()
            .iter()
            .filter_map(|peer| if peer.address.is_zero() { None } else { Some(format!("{}:{}", peer.host(), peer.port))})
            .collect()
    }

    /// Using Masternode List for connectivitity
    pub fn use_masternode_list_with_connectivity_nonce(&mut self, masternode_list: &MasternodeList, connectivity_nonce: u64) {
        self.masternode_list = Some(masternode_list);
        self.masternode_list_connectivity_nonce = connectivity_nonce;
        let connected = self.connected;

        if let Some(peers) = self.peers_with_connectivity_nonce(masternode_list, 500, connectivity_nonce) {
            self.clear_peers();
            self.peers = peers;
            self.remove_misbehaving_peers();
        } else {
            self.peers = vec![];
        }
        self.sort_peers();

        if self.peers.len() > 1 && self.peers.len() < 1000 {
            // peer relaying is complete when we receive <1000
            self.save_peers();
        }
        if connected {
            self.connect();
        }
        DispatchContext::main_context().queue(||
            NotificationCenter::post(Notification::PeersDidChange(self.chain)));
    }

    /// Peer Registration

    pub fn connect(&mut self) {
        self.desired_state == PeerManagerDesiredState::Connected;
        DispatchContext::network_context().queue(|| {
            if self.chain.syncs_blockchain() && !self.chain.can_construct_a_filter() {
                // check to make sure the wallet has been created if only are a basic wallet with no dash features
                return;
            }
            if self.connect_failures >= MAX_CONNECT_FAILURES {
                // this attempt is a manual retry
                self.connect_failures = 0;
            }
            if self.chain.terminal_header_sync_progress() < 1.0 {
                self.chain.reset_terminal_sync_start_height();
                // todo: background ops
                /*#if TARGET_OS_IOS
                if (self.blockLocatorsSaveTaskId == UIBackgroundTaskInvalid) { // start a background task for the chain sync
                    self.blockLocatorsSaveTaskId = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
                        dispatch_async(self.networkingQueue, ^{
                            [self.chain saveBlockLocators];
                        });
                        [self chainSyncStopped];
                    }];
                }
                #endif*/
            }
            if self.chain.chain_sync_progress() < 1.0 {
                self.chain.reset_chain_sync_start_height();
                // todo: background ops
                /*#if TARGET_OS_IOS
                if (self.terminalHeadersSaveTaskId == UIBackgroundTaskInvalid) { // start a background task for the chain sync
                    self.terminalHeadersSaveTaskId = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
                        dispatch_async(self.networkingQueue, ^{
                            [self.chain saveTerminalBlocks];
                        });
                        [self chainSyncStopped];
                    }];
                }
                #endif*/
            }

            self.mutable_connected_peers = self.mutable_connected_peers.iter().filter(|peer| peer.status() != PeerStatus::Disconnected).collect();
            self.fixed_peer = if let Some(trusted) = self.trusted_peer_host() {
                Peer::peer_with_host(trusted, self.chain)
            } else {
                None
            };
            self.max_connect_count = if self.fixed_peer.is_some() { 1 } else { PEER_MAX_CONNECTIONS };
            if self.connected_peers.len() >= self.max_connect_count {
                // already connected to maxConnectCount peers
                return;
            }
            let mut peers = self.peers.clone();
            if peers.len() > 100 {
                peers.drain(100..);
            }
            if peers.len() > 0 && self.connected_peers.len() < self.max_connect_count {
                let earliest_wallet_creation_time = self.chain.earliest_wallet_creation_time();
                while !peers.is_empty() && self.connected_peers.len() < self.max_connect_count {
                    // pick a random peer biased towards peers with more recent timestamps
                    if let Some(peer) = peers.get_mut(thread_rng().gen_range(0..peers.len())) {
                        if !self.connected_peers.contains(&peer) {
                            // todo: implement delegate traits for peer
                            //[peer setChainDelegate:self.chain.chainManager peerDelegate:self transactionDelegate:self.transactionManager governanceDelegate:self.governanceSyncManager sporkDelegate:self.sporkManager masternodeDelegate:self.masternodeManager queue:self.networkingQueue];
                            peer.earliest_key_time = earliest_wallet_creation_time;
                            self.mutable_connected_peers.insert(*peer);
                            println!("Will attempt to connect to peer {}", peer.host());
                            peer.connect();
                        }
                        if let Some(index) = peers.iter().position(|p| p == peer) {
                            peers.remove(index);
                        }
                    }
                }
            }
            if self.connected_peers.len() == 0 {
                self.chain_sync_stopped();
                DispatchContext::main_context().queue(||
                    NotificationCenter::post(
                        Notification::ChainSyncFailed(self.chain, &Some(Error::NoPeersFound))));
            }
        });
    }

    pub fn disconnect(&mut self) {
        self.desired_state == PeerManagerDesiredState::Disconnected;
        DispatchContext::network_context().queue(|| {
            self.connected_peers.iter().for_each(|mut peer| {
                // prevent futher automatic reconnect attempts
                self.connect_failures = MAX_CONNECT_FAILURES;
                peer.disconnect();
            });
        });
    }

    pub fn disconnect_download_peer<F: FnMut(bool)>(&mut self, error: Option<Error>, completion: F) {
        if let Some(peer) = &mut self.download_peer {
            peer.disconnect_with_error(error);
        }
        DispatchContext::network_context().queue(|| {
            // disconnect the current download peer so a new random one will be selected
            if let Some(peer) = &self.download_peer {
                if let Some(pos) = self.peers.iter().position(|x| x == peer) {
                    self.peers.remove(pos);
                }
            }
            completion(true);
        });
    }

    pub fn sync_timeout(&mut self) {
        let now = SystemTime::seconds_since_1970();
        if now - self.chain.last_chain_relay_time < PROTOCOL_TIMEOUT {
            // TODO: implement cancellation with token
            // the download peer relayed something in time, so restart timer
            // [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];
            // [self performSelector:@selector(syncTimeout)
            // withObject:nil
            // afterDelay:PROTOCOL_TIMEOUT - (now - self.chainManager.lastChainRelayTime)];
            return;
        }

        self.disconnect_download_peer(Some(Error::SyncTimeout), |success| {});
    }

    pub fn chain_sync_stopped(&self) {
        DispatchContext::main_context().queue(|| {
            // TODO: implement cancellation with token
            // TODO: background ops
            //[NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];
            /*#if TARGET_OS_IOS
            if (self.terminalHeadersSaveTaskId != UIBackgroundTaskInvalid) {
                [[UIApplication sharedApplication] endBackgroundTask:self.terminalHeadersSaveTaskId];
                self.terminalHeadersSaveTaskId = UIBackgroundTaskInvalid;
            }

            if (self.blockLocatorsSaveTaskId != UIBackgroundTaskInvalid) {
                [[UIApplication sharedApplication] endBackgroundTask:self.blockLocatorsSaveTaskId];
                self.blockLocatorsSaveTaskId = UIBackgroundTaskInvalid;
            }
            #endif*/
        });
    }

    pub fn peer_connected(&mut self, peer: &mut Peer) {
        let now = SystemTime::seconds_since_1970();
        if peer.timestamp > now + 2 * 60 * 60 || peer.timestamp < now - 2 * 60 * 60 {
            //timestamp sanity check
            peer.timestamp = now;
        }
        self.connect_failures = 0;
        println!("{}:{} connected with lastblock {} (our last header {} - last block {})", peer.host, peer.port, peer.last_block_height, self.chain.last_terminal_block_height(), self.chain.last_sync_block_height);

        // drop peers that don't carry full blocks, or aren't synced yet
        // TODO: XXXX does this work with 0.11 pruned nodes?
        if peer.services & SERVICES_NODE_NETWORK == 0 || peer.last_block_height + 10 < self.chain.last_sync_block_height {
            peer.disconnect_with_error(Some(Error::ServiceNetworkError(peer.clone())));
            return;
        }

        // drop peers that don't support SPV filtering
        if peer.version >= 70206 && peer.services & SERVICES_NODE_BLOOM == 0 {
            peer.disconnect_with_error(Some(Error::BloomFilteringNotSupported(peer.clone())));
            return;
        }

        if self.connected {
            if !self.chain.syncs_blockchain() { return; }

            if self.chain.can_construct_a_filter() {
                peer.send_filterload_message(self.transaction_manager().tranactions_bloom_filter_for_peer(peer).data);
                // publish pending tx
                peer.send_inv_message_for_hashes(self.transaction_manager().published_callback.keys().collect(), InvType::Tx);
            } else {
                peer.send_filterload_message(BloomFilter::empty_bloom_filter_data());
            }

            if self.chain.estimated_block_height() >= peer.last_block_height || self.chain.last_sync_block_height >= peer.last_block_height {
                if self.chain.last_sync_block_height < self.chain.estimated_block_height() {
                    println!("lastSyncBlockHeight {}, estimatedBlockHeight {}", self.chain.last_sync_block_height, self.chain.estimated_block_height());
                    return; // don't get mempool yet if we're syncing
                }
                peer.send_ping_message(|success| {
                    if !success {
                        println!("[DSTransactionManager] fetching mempool ping on connection failure peer {}", peer.host());
                        return;
                    }
                    println!("[DSTransactionManager] fetching mempool ping on connection success peer {}", peer.host());
                    let callback: MempoolTransactionCallback = |success, needed, interrupted_by_disconnect| {
                        if !success {
                            if !needed {
                                println!("[DSTransactionManager] fetching mempool message on connection not needed (already happening) peer {}", peer.host());
                            } else if interrupted_by_disconnect {
                                println!("[DSTransactionManager] fetching mempool message on connection failure peer {}", peer.host());
                            } else {
                                println!("[DSTransactionManager] fetching mempool message on connection failure disconnect peer {}", peer.host());
                            }
                            return;
                        }
                        println("[DSTransactionManager] fetching mempool message on connection success peer {}", peer.host());
                        peer.synced = true;
                        self.transaction_manager().remove_unrelayed_transactions_from_peer(peer);
                        if self.masternode_list.is_none() {
                            // request a list of other dash peers
                            peer.send_getaddr_message();
                        }
                        DispatchContext::main_context().queue(||
                            NotificationCenter::post(Notification::TransactionStatusDidChange(self.chain)));
                    };

                    peer.send_mempool_message(self.transaction_manager().published_tx.keys().collect(),Some(callback))
                });
                DispatchContext::main_context().queue(||
                    NotificationCenter::post(Notification::PeersConnectedDidChange(self.chain)));
                return; // we're already connected to a download peer
            }
        }

        // select the peer with the lowest ping time to download the chain from if we're behind
        // BUG: XXX a malicious peer can report a higher lastblock to make us select them as the download peer, if two
        // peers agree on lastblock, use one of them instead
        let really_connected_peers = self.connected_peers.iter().filter(|peer| peer.status() == PeerStatus::Connected).collect();
        if !self.chain.is_devnet_any() && really_connected_peers.len() < self.max_connect_count {
            // we didn't connect to all connected peers yet
            return;
        }
        let mut best_peer = peer.clone();
        really_connected_peers.iter().for_each(|peer| {
            if (peer.ping_time < best_peer.ping_time && peer.last_block_height >= best_peer.last_block_height) || peer.last_block_height > best_peer.last_block_height {
                best_peer = peer;
            }
            self.chain.set_estimated_block_height(peer.last_block_height, &peer, really_connected_peers.len() * 2 / 3);
        });
        if let Some(peer) = &mut self.download_peer {
            peer.disconnect();
        }
        self.download_peer = Some(best_peer);
        self.connected = true;

        if self.chain.syncs_blockchain() && self.chain.can_construct_a_filter() {
            best_peer.send_filterload_message(self.transaction_manager().transactions_bloom_filter_for_peer(best_peer).data);
        }
        best_peer.current_block_height = self.chain.last_sync_block_height;
        if self.chain.syncsBlockchain() && ((self.chain.last_sync_block_height != self.chain.last_terminal_block_height()) ||
            (self.chain.last_sync_block_height < best_peer.last_block_height)) {
            // start blockchain sync
            self.reset_last_relayed_item_time();
            DispatchContext::main_context().queue(|| { // setup a timer to detect if the sync stalls
                // TODO: implement cancellation with token
                // [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];
                // [self performSelector:@selector(syncTimeout) withObject:nil afterDelay:PROTOCOL_TIMEOUT];
                //
                NotificationCenter::post(Notification::TransactionStatusDidChange(self.chain));
                self.chain.chain_will_start_syncing_blockchain();
                self.chain.chain_should_start_syncing_blockchain(&mut best_peer);
            });
        } else {
            // we're already synced
            self.chain_finished_syncing_transactions_and_blocks(self.chain, None, true);
        }
        DispatchContext::main_context().queue(|| {
            NotificationCenter::post(Notification::PeersConnectedDidChange(self.chain));
            NotificationCenter::post(Notification::PeersDownloadPeerDidChange(self.chain));
        });
    }

    pub fn peer_disconnected_with_error(&mut self, peer: &Peer, error: Option<Error>) {
        println!("{}:{} disconnected{}{}", peer.host(), peer.port, if error.is_some() { ", " } else { "" }, if error.is_some() { error.unwrap().message() } else { "" });
        if let Some(err) = error {
            if err.is_app_level() {
                self.peer_misbehaving(peer, err.message());
            } else {
                if let Some(pos) = self.peers.iter().position(|x| *x == bad_peer) {
                    self.peers.remove(pos);
                }
                self.connect_failures += 1;
            }
        }

        self.transaction_manager().clear_transaction_relays_for_peer(peer);
        if self.download_peer.unwrap() == *peer {
            // download peer disconnected
            self.connected = false;
            self.chain.remove_estimated_block_heights_of_peer(peer);
            self.download_peer = None;
            if self.connect_failures > MAX_CONNECT_FAILURES {
                self.connect_failures = MAX_CONNECT_FAILURES;
            }
        }

        if !self.connected && self.connect_failures == MAX_CONNECT_FAILURES {
            self.chain_sync_stopped();
            // clear out stored peers so we get a fresh list from DNS on next connect attempt
            self.mutable_misbehaving_peers.clear();
            self.context.perform_block_and_wait(|context| {
                PeerEntity::delete_all_peers_for_chain(self.chain.r#type(), context)
                    .expect("Can't delete stored peers");
            });
            self.peers.clear();
            DispatchContext::main_context().queue(||
                NotificationCenter::post(
                    Notification::ChainSyncFailed(self.chain, &error)))
        } else if self.connect_failures < MAX_CONNECT_FAILURES {
            DispatchContext::main_context().queue(|| {
                // TODO: impl background ops
                // #if TARGET_OS_IOS
                // if ((self.desiredState == DSPeerManagerDesiredState_Connected) && (self.terminalHeadersSaveTaskId != UIBackgroundTaskInvalid ||
                //     [UIApplication sharedApplication].applicationState != UIApplicationStateBackground)) {
                // [self connect]; // try connecting to another peer
                // }
                // #else
                // if (self.desiredState == DSPeerManagerDesiredState_Connected) {
                //     [self connect]; // try connecting to another peer
                // }
                // #endif

            });
        }
        DispatchContext::main_context().queue(|| {
            NotificationCenter::post(Notification::PeersConnectedDidChange(self.chain));
            NotificationCenter::post(Notification::PeersDownloadPeerDidChange(self.chain));
        });
    }

    fn remove_misbehaving_peers(&mut self) {
        // [self.peers minusSet:self.misbehavingPeers];
        self.mutable_misbehaving_peers.iter().for_each(|bad_peer| {
            if let Some(pos) = self.peers.iter().position(|x| x == bad_peer) {
                self.peers.remove(pos);
            }
        });
    }

    pub fn peers_relayed(&mut self, peer: &Peer, peers: Vec<Peer>) {
        if self.masternode_list.is_some() {
            return;
        }
        println!("{}:{} relayed {} peer(s)", peer.host(), peer.port, peers.len());
        self.peers.extend(peers);
        self.remove_misbehaving_peers();
        self.sort_peers();
        // limit total to 2500 peers
        if self.peers.len() > 2500 {
            self.peers.drain(2500..self.peers.len() - 2500);
        }
        let now = SystemTime::seconds_since_1970();
        // remove peers more than 3 hours old, or until there are only 1000 left
        while self.peers.len() > 1000 && self.peers.last().unwrap().timestamp + 3 * 60 * 60 < now {
            self.peers.remove(self.peers.len() - 1);
        }
        if peers.len() > 1 && peers.len() < 1000 {
            // peer relaying is complete when we receive <1000
            self.save_peers();
        }
        DispatchContext::main_context().queue(||
            NotificationCenter::post(
                Notification::PeersDidChange(self.chain)));
    }
}
