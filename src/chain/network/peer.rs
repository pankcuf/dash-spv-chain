use std::collections::HashSet;
use std::env;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::{Hash, sha256d};
use byte::{BytesExt, Iter};
use byte::ctx::{Bytes, NULL, Str};
use chrono::NaiveDateTime;
use diesel::query_builder::AsChangeset;
use diesel::Table;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::{UInt128, UInt256};
use crate::crypto::byte_util::{AsBytes, Zeroable};
use crate::crypto::data_ops::{hex_with_data, short_hex_string_from};
use crate::models::MasternodeEntry;
use crate::chain::tx::transaction::ITransaction;
use secp256k1::rand::{Rng, thread_rng};
use crate::chain::block::{IBlock, MerkleBlock};
use crate::chain::chain::Chain;
use crate::chain::chain_sync_phase::ChainSyncPhase;
use crate::chain::merkle_block::MerkleBlock;
use crate::chain::options::sync_type::SyncType;
use crate::chain::{governance, spork};
use crate::chain::tx;
use crate::chain::chain_lock::ChainLock;
use crate::chain::dispatch_context::DispatchContext;
use crate::chain::spork::manager::PeerSporkDelegate;
use crate::chain::spork::Spork;
use crate::chain::sync_count_info::SyncCountInfo;
use crate::manager::governance_sync_manager::{GovernanceSyncManager, PeerGovernanceDelegate};
use crate::manager::masternode_manager::PeerMasternodeDelegate;
use crate::manager::peer_manager;
use crate::manager::peer_manager::{Error, SERVICES_NODE_NETWORK};
use crate::manager::transaction_manager::{PeerTransactionDelegate, TransactionManager};
use crate::chain::network::governance_request_state::GovernanceRequestState;
use crate::chain::network::message::inv_type::InvType;
use crate::chain::network::message::r#type::Type;
use crate::chain::network::message::request::{GovernanceHashesRequest, GovernanceSyncRequest, IRequest, Request};
use crate::chain::network::peer_type::PeerType;
use crate::chain::network::{message, PeerStatus};
use crate::chain::network::message::r#type::Type::Inv;
use crate::chain::tx::instant_send_transaction_lock::InstantSendTransactionLock;
use crate::schema::peers;
use crate::storage::models::common::peer::NewPeerEntity;
use crate::storage::models::entity::EntityUpdates;
use crate::util::{TimeUtil, x11_hash};
use crate::util::crypto::x11_hash;
use crate::util::time::TimeUtil;

pub const WEEK_TIME_INTERVAL: u64 = 604800; //7*24*60*60
pub const DAY_TIME_INTERVAL: u64 = 86400;   //24*60*60
pub const DAYS_3_TIME_INTERVAL: u64 = 86400 * 3;
pub const HOUR_TIME_INTERVAL: u64 = 3600;
pub const HOURS_3_TIME_INTERVAL: u64 = 10800;
/// we don't provide full blocks to remote nodes
pub const ENABLED_SERVICES: u64 = 0;
pub const LOCAL_HOST: u32 = 0x7f000001;
pub const MAX_MSG_LENGTH: usize = 0x02000000;
pub const MAX_GETDATA_HASHES: usize = 50000;

pub type PongCallback = fn(success: bool);
pub type MempoolTransactionCallback = fn(success: bool, needed: bool, interrupted_by_disconnect: bool);

const FNV32_PRIME: u32 = 0x01000193;
const FNV32_OFFSET: u32 = 0x811C9dc5;

#[derive(Copy, Clone, Debug)]
pub struct Peer {
    pub address: UInt128,
    pub port: u16,
    pub timestamp: u64,
    pub services: u64,
    pub priority: u32,
    pub status: PeerStatus,
    pub version: u32,
    pub last_block_hash: UInt256,
    pub last_block_height: u32,
    pub useragent: String,
    pub misbehaving: i16,
    pub low_preference_till: u64,

    pub ping_time: u64,
    local_nonce: u64,
    ping_start_time: u64,
    /// headers or block->totalTx per second being relayed
    relay_speed: u64,
    relay_start_time: u64,

    pub last_requested_masternode_list: Option<u64>,
    pub last_requested_governance_sync: Option<u64>,
    /// set this to the timestamp when the wallet was created to improve initial sync time (interval since reference date)
    pub earliest_key_time: u64,

    pub chain: &'static Chain,

    /// set this when wallet addresses need to be added to bloom filter
    pub needs_filter_update: bool,
    /// set this to local block height (helps detect tarpit nodes)
    pub current_block_height: u32,
    /// use this to keep track of peer state
    pub synced: bool,

    /// minimum tx fee rate peer will accept
    pub fee_per_byte: u64,

    sent_getaddr: bool,
    sent_getdatatxblocks: bool,
    sent_getdatamasternode: bool,
    sent_filter: bool,
    sent_getblocks: bool,
    sent_getheaders: bool,
    sent_mempool: bool,
    sent_verack: bool,
    got_verack: bool,


    received_orphan_count: u32,

    pong_handlers: Vec<PongCallback>,

    mempool_transaction_callback: Option<MempoolTransactionCallback>,
    mempool_request_time: u64,

    known_block_hashes: Vec<UInt256>,
    known_chain_lock_hashes: Vec<UInt256>,
    known_tx_hashes: Vec<UInt256>,
    known_is_lock_hashes: Vec<UInt256>,
    known_isd_lock_hashes: Vec<UInt256>,
    known_governance_object_hashes: Vec<UInt256>,
    known_governance_vote_hashes: Vec<UInt256>,

    governance_request_state: GovernanceRequestState,

    current_block: Option<MerkleBlock>,
    current_block_tx_hashes: Option<Vec<UInt256>>,


    transaction_delegate: &'static TransactionManager,
    governance_delegate: &'static dyn PeerGovernanceDelegate,
    spork_delegate: &'static dyn PeerSporkDelegate,
    masternode_delegate: &'static dyn PeerMasternodeDelegate,

    delegate_context: &'static DispatchContext,
}

impl Peer {

    pub(crate) fn peer_with_host(host: &str, chain: &Chain) -> Option<Peer> {
        todo!()
    }

    pub fn new(address: UInt128, port: u16, timestamp: u64, services: u64, chain: &Chain) -> Self {
        Self {
            address,
            port,
            timestamp,
            services,
            priority: 0,
            status: PeerStatus::Unknown,
            governance_request_state: GovernanceRequestState::None,
            chain,
            transaction_delegate: chain.transaction_manager(),
            governance_delegate: chain.governance_sync_manager(),
            masternode_delegate: chain.masternode_manager(),
            spork_delegate: chain.spork_manager(),
            ..Default::default()
        }
    }

    pub fn init_with_masternode(masternode: &MasternodeEntry, chain: &Chain) -> Self {
        Self::new(
            masternode.socket_address.ip_address,
            if masternode.socket_address.port == 0 { chain.params.standard_port } else { masternode.socket_address.port },
            0,
            0,
            chain)
    }

    pub fn init_with_address(address: UInt128, port: u16, chain: &Chain, timestamp: u64, services: u64) -> Self {
        Self::new(
            address,
            if port == 0 { chain.params.standard_port } else { port },
            timestamp,
            services,
            chain)
    }

    pub fn location(&self) -> String {
        format!("{}:{}", self.host(), self.port)
    }

    pub fn host(&self) -> String {
        IpAddr::from(self.address.0).to_string()
    }

    pub fn status(&self) -> PeerStatus {
        todo!()
    }

    pub fn r#type(&self) -> PeerType {
        todo!()
    }

    // pub fn useragent(&self) -> String {
    //     self.chain.user_agent()
    // }

    pub fn send_request(&self, request: Request) {
        let r#type = request.r#type();
        let payload = request.to_data();
        //println!("{}:{} sendRequest: [{}]: {}}", self.host(), self.port, r#type, payload.to_hex());
        self.send_message(payload, r#type);
    }

    fn send_message(&self, message: Vec<u8>, r#type: Type) {
        if message.len() > MAX_MSG_LENGTH {
            println!("{}:{} failed to send {}, length {} is too long", self.host(), self.port, r#type.into(), message.len());
            return;
        }
        // TODO: implement p2p message sending
        /*
        if (!self.runLoop) return;
        CFRunLoopPerformBlock([self.runLoop getCFRunLoop], kCFRunLoopCommonModes, ^{
            LOCK(self.outputBufferSemaphore);
            [self.outputBuffer appendMessage:message type:type forChain:self.chain];
            while (self.outputBuffer.length > 0 && self.outputStream.hasSpaceAvailable) {
                NSInteger l = [self.outputStream write:self.outputBuffer.bytes maxLength:self.outputBuffer.length];
                if (l > 0) [self.outputBuffer replaceBytesInRange:NSMakeRange(0, l) withBytes:NULL length:0];
                //if (self.outputBuffer.length == 0) DSLog(@"%@:%u output buffer cleared", self.host, self.port);
            }
            UNLOCK(self.outputBufferSemaphore);
        });
        CFRunLoopWakeUp([self.runLoop getCFRunLoop]);
        */
    }

    fn send_version_message(&mut self) {
        self.local_nonce = bound + thread_rng().gen::<u64>() << 32 | thread_rng().gen::<u64>();
        let user_agent = self.chain.user_agent();
        let request = Request::Version(self.address, self.port, self.chain.params.protocol_version, self.services, self.chain.params.standard_port, self.local_nonce, user_agent);

        self.ping_start_time = SystemTime::seconds_since_1970();

        //println!("{}:{} {} sending version with protocol version {} user agent {}", self.host(), self.port, "", self.chain.params.protocol_version, user_agent);
        self.send_request(request);
    }

    pub fn send_verack_message(&mut self) {
        self.send_request(Request::Default(Type::Verack));
        self.sent_verack = true;
        self.did_connect();
    }

    pub fn send_filterload_message(&mut self, filter: Vec<u8>) {
        self.sent_filter = true;
        println!("Sending filter with fingerprint {} to node {} {}", "<REDACTED>", self.host(), "");
        self.send_request(Request::FilterLoad(filter));
    }

    pub fn mempool_timeout(&mut self) {
        println!("[DSPeer] mempool time out {}", self.host());
        let completion = self.mempool_transaction_callback;
        self.send_ping_message(|success| {
            if let Some(completion) = completion {
                completion(success, true, false);
            }
        });
        self.mempool_transaction_callback = None;
    }

    pub fn send_mempool_message(&mut self, published_tx_hashes: Vec<UInt256>, completion: Option<MempoolTransactionCallback>) {
        println!("{}:{} send_mempool_message", self.host(), self.port);
        self.known_tx_hashes.extend(published_tx_hashes);
        self.sent_mempool = true;
        if let Some(callback) = completion {
            // TODO: impl async callback
            if let Some(mempool_callback) = self.mempool_transaction_callback {
                //dispatch_async(self.delegateQueue, ^{
                if self.status() == PeerStatus::Connected {
                    callback(false, false, false);
                }
                //});
            } else {
                self.mempool_transaction_callback = completion;
                //dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(MEMPOOL_TIMEOUT * NSEC_PER_SEC)), self.delegateQueue, ^{
                if SystemTime::seconds_since_1970() - self.mempool_request_time >= MEMPOOL_TIMEOUT {
                    self.mempool_timeout();
                }
                //});
            }
        }
        self.mempool_request_time = SystemTime::seconds_since_1970();
        self.send_request(Request::Default(Type::Mempool));
    }

    // the standard blockchain download protocol works as follows (for SPV mode):
    // - local peer sends getblocks
    // - remote peer reponds with inv containing up to 500 block hashes
    // - local peer sends getdata with the block hashes
    // - remote peer responds with multiple merkleblock and tx messages
    // - remote peer sends inv containg 1 hash, of the most recent block
    // - local peer sends getdata with the most recent block hash
    // - remote peer responds with merkleblock
    // - if local peer can't connect the most recent block to the chain (because it started more than 500 blocks behind), go
    //   back to first step and repeat until entire chain is downloaded
    //
    // we modify this sequence to improve sync performance and handle adding bip32 addresses to the bloom filter as needed:
    // - local peer sends getheaders
    // - remote peer responds with up to 2000 headers
    // - local peer immediately sends getheaders again and then processes the headers
    // - previous two steps repeat until a header within a week of earliestKeyTime is reached (further headers are ignored)
    // - local peer sends getblocks
    // - remote peer responds with inv containing up to 500 block hashes
    // - local peer sends getdata with the block hashes
    // - if there were 500 hashes, local peer sends getblocks again without waiting for remote peer
    // - remote peer responds with multiple merkleblock and tx messages, followed by inv containing up to 500 block hashes
    // - previous two steps repeat until an inv with fewer than 500 block hashes is received
    // - local peer sends just getdata for the final set of fewer than 500 block hashes
    // - remote peer responds with multiple merkleblock and tx messages
    // - if at any point tx messages consume enough wallet addresses to drop below the bip32 chain gap limit, more addresses
    //   are generated and local peer sends filterload with an updated bloom filter
    // - after filterload is sent, getdata is sent to re-request recent blocks that may contain new tx matching the filter
    pub fn send_getheaders_message_with_locators(&mut self, locators: Vec<UInt256>, hash_stop:UInt256) {
        let request = Request::GetHeaders(locators, hash_stop, self.chain.params.protocol_version);
        if self.relay_start_time == 0 {
            self.relay_start_time = SystemTime::seconds_since_1970();
        }
        self.send_request(request);
    }

    pub fn send_getblocks_message_with_locators(&mut self, locators: Vec<UInt256>, hash_stop:UInt256) {
        // DSGetBlocksRequest *request = [DSGetBlocksRequest requestWithLocators:locators andHashStop:hashStop protocolVersion:self.chain.protocolVersion];
        let request = Request::GetBlocks(locators, hash_stop, self.chain.params.protocol_version);
        self.sent_getblocks = true;
        self.send_request(request);
    }

    pub fn send_inv_message_for_hashes(&mut self, inv_hashes: Vec<UInt256>, inv_type: InvType) {
        println("{}:{} sending inv message of type {} hashes count {}", self.host(), self.port, inv_type.name(), inv_hashes.len());
        let mut hashes = inv_hashes.clone();
        self.known_tx_hashes.iter().for_each(|tx_hash| {
            if let Some(pos) = hashes.iter().position(|x| *x == tx_hash) {
                hashes.remove(pos);
            }
        });
        if hashes.is_empty() {
            return;
        }
        let request = Request::Inv(inv_type, &hashes);
        self.send_request(request);
        todo!();
        match inv_type {
            InvType::Tx => {
                //[self.known_tx_hashes unionOrderedSet:hashes];
                hashes.iter().for_each(|hash| {
                    if !self.known_tx_hashes.contains(hash) {
                        self.known_tx_hashes.push(hash.clone());
                    }
                });
            },
            InvType::GovernanceObjectVote => {
                //[self.known_governance_vote_hashes unionOrderedSet:hashes];
                hashes.iter().for_each(|hash| {
                    if !self.known_governance_vote_hashes.contains(hash) {
                        self.known_governance_vote_hashes.push(hash.clone());
                    }
                });

            },
            InvType::GovernanceObject => {
                //[self.knownGovernanceObjectHashes unionOrderedSet:hashes];
                hashes.iter().for_each(|hash| {
                    if !self.known_governance_object_hashes.contains(hash) {
                        self.known_governance_object_hashes.push(hash.clone());
                    }
                });
            },
            InvType::Block => {
                //[self.knownBlockHashes unionOrderedSet:hashes];
                hashes.iter().for_each(|hash| {
                    if !self.known_block_hashes.contains(hash) {
                        self.known_block_hashes.push(hash.clone());
                    }
                });

            },
            InvType::ChainLockSignature => {
                //[self.knownChainLockHashes unionOrderedSet:hashes];
                hashes.iter().for_each(|hash| {
                    if !self.known_block_hashes.contains(hash) {
                        self.known_chain_lock_hashes.push(hash.clone());
                    }
                });

            },
            _ => {}
        }
    }

    pub fn send_transaction_inv_messages_for_transaction_hashes(&mut self, tx_inv_hashes: Option<Vec<UInt256>>, tx_lock_request_inv_hashes: Option<Vec<UInt256>>) {
        let mut tx_hashes = tx_inv_hashes.unwrap_or(vec![]);
        let mut tx_lock_request_hashes = tx_lock_request_inv_hashes.unwrap_or(vec![]);
        self.known_tx_hashes.iter().for_each(|tx_hash| {
            if let Some(pos) = tx_hashes.iter().position(|x| *x == tx_hash) {
                tx_hashes.remove(pos);
            }
            if let Some(pos) = tx_lock_request_hashes.iter().position(|x| *x == tx_hash) {
                tx_lock_request_hashes.remove(pos);
            }
        });
        if tx_hashes.is_empty() && tx_lock_request_hashes.is_empty() {
            return;
        }
        self.send_request(Request::TransactionInv(&tx_hashes, &tx_lock_request_hashes));

        // [self.knownTxHashes unionOrderedSet:tx_hashes]
        tx_hashes.iter().for_each(|tx_hash| {
            if !self.known_tx_hashes.contains(tx_hash) {
                self.known_tx_hashes.push(tx_hash.clone());
            }
        });
        // [self.knownTxHashes unionOrderedSet:tx_lock_request_hashes]
        tx_lock_request_hashes.iter().for_each(|tx_hash| {
            if !self.known_tx_hashes.contains(tx_hash) {
                self.known_tx_hashes.push(tx_hash.clone());
            }
        });
    }

    pub fn send_getdata_message_for_tx_hash(&mut self, tx_hash: UInt256) {
        let sync_type = &self.chain.options.sync_type;
        if sync_type & SyncType::GetsNewBlocks == 0 {
            return;
        }
        self.send_request(Request::GetDataForTransactionHash(tx_hash));
    }

    pub fn send_getdata_message_with_tx_hashes(&mut self, tx_hashes: Option<&Vec<UInt256>>, is_lock_hashes: Option<&Vec<UInt256>>, isd_lock_hashes: Option<&Vec<UInt256>>, block_hashes: Option<&Vec<UInt256>>, c_lock_hashes: Option<&Vec<UInt256>>) {
        let sync_type = &self.chain.options.sync_type;
        if sync_type & SyncType::GetsNewBlocks == 0 {
            return;
        }
        let tx_hashes_len = if tx_hashes.is_some() { tx_hashes.unwrap().len() } else { 0 };
        let is_lock_hashes_len = if is_lock_hashes.is_some() { is_lock_hashes.unwrap().len() } else { 0 };
        let isd_lock_hashes_len = if isd_lock_hashes.is_some() { isd_lock_hashes.unwrap().len() } else { 0 };
        let block_hashes_len = if block_hashes.is_some() { block_hashes.unwrap().len() } else { 0 };
        let c_lock_hashes_len = if c_lock_hashes.is_some() { c_lock_hashes.unwrap().len() } else { 0 };
        let total_hashes = tx_hashes_len + is_lock_hashes_len + isd_lock_hashes_len + block_hashes_len + c_lock_hashes_len;
        if total_hashes > MAX_GETDATA_HASHES {
            // limit total hash count to MAX_GETDATA_HASHES
            println!("{}:{} couldn't send getdata, {} is too many items, max is {}", self.host(), self.port, total_hashes, MAX_GETDATA_HASHES);
            return;
        } else if total_hashes == 0 {
            return;
        }
        self.sent_getdatatxblocks = true;
        self.send_request(Request::GetDataForTransactionHashes(
            tx_hashes,
            block_hashes,
            is_lock_hashes,
            isd_lock_hashes,
            c_lock_hashes
        ));
    }

    pub fn send_governance_request(&mut self, request: GovernanceHashesRequest) {
        return;
        if hashes.len() > MAX_GETDATA_HASHES { // limit total hash count to MAX_GETDATA_HASHES
            println!("{}:{} couldn't send governance votes getdata, {} is too many items, max is {}", self.host(), self.port, hashes.len(), MAX_GETDATA_HASHES);
            return;
        } else if hashes.len() == 0 {
            println!("{}:{} couldn't send governance getdata, there is no items", self.host(), self.port);
            return;
        }
        self.send_request(request.message_request());
    }

    pub fn send_getaddr_message(&mut self) {
        self.sent_getaddr = true;
        self.send_request(Request::Default(Type::Getaddr));
    }

    pub fn send_ping_message(&mut self, callback: fn(bool)) {
        // TODO: async?
        //dispatch_async(self.delegateQueue, ^{
        if let Some(callback) = callback {
            self.pong_handlers.push(callback);
        }
        let request = Request::Ping(self.local_nonce);
        self.ping_start_time = SystemTime::seconds_since_1970();
        self.send_request(request);
        //});
    }

    /// re-request blocks starting from blockHash, useful for getting any additional transactions after a bloom filter update
    pub fn rerequest_blocks_from(&mut self, block_hash: &UInt256 ) {
        if let Some(pos) = self.known_block_hashes.iter().position(|hash| hash == block_hash) {
            self.known_block_hashes.drain(0..pos);
            println!("{}:{} re-requesting {} blocks", self.host(), self.port, self.known_block_hashes.len());
            self.send_getdata_message_with_tx_hashes(None, None, None, Some(&self.known_block_hashes), None);
        }
    }

    /// send Dash Sporks
    pub fn send_get_sporks(&self) {
        self.send_request(Request::Default(Type::GetSporks))
    }

    /// Send Dash Governance

    /// Governance Synchronization for Votes and Objects
    pub fn send_governance_sync_request(&mut self, request: GovernanceSyncRequest) {
        // Make sure we aren't in a governance sync process
        println!("{}:{} Requesting Governance Object Vote Hashes", self.host(), self.port);
        if self.governance_request_state != GovernanceRequestState::None {
            println!("{}:{} Requesting Governance Object Hashes out of resting state", self.host(), self.port);
            return;
        }
        self.governance_request_state = request.state();
        self.send_request(request.message_request());
        if request.state() == GovernanceRequestState::GovernanceObjectHashes {
            // we aren't afraid of coming back here within 5 seconds because a peer can only sendGovSync once every 3 hours
            //dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if self.governance_request_state == GovernanceRequestState::GovernanceObjectHashes {
                println!("{}:{} Peer ignored request for governance object hashes", self.host(), self.port);
                //[self.governanceDelegate peer:self ignoredGovernanceSync:DSGovernanceRequestState_GovernanceObjectHashes];
            }
            //});
        }
    }

    pub fn send_gov_object_vote(&self, vote: governance::Vote) {
        self.send_message(vote.data_message(), Type::Govobjvote);
    }

    pub fn send_gov_object(&self, object: governance::Object) {
        self.send_message(object.data_message(), Type::Govobj);
    }

    /// Accept
    pub fn accept_message(&mut self, message: &[u8], r#type: Type) {
        if self.current_block.is_some() && (!(r#type == Type::Tx || r#type == Type::Ix || r#type == Type::Islock || r#type == Type::Isdlock))  {
            let hash = cblock.block_hash();
            self.current_block = None;
            self.current_block_tx_hashes = None;
            self.disconnect_with_error(Some(Error::Default(format!("incomplete merkleblock {}, got {}", hash, r#type.into()))));
            return;
        }
        match r#type {
            Type::WrongType => {}
            Type::Version => { self.accept_version_message(message); },
            Type::Verack => {}
            Type::Addr => {}
            Type::Inv => {}
            Type::Getdata => {}
            Type::NotFound => {}
            Type::Getblocks => {}
            Type::Getheaders => {}
            Type::Tx => {}
            Type::Ix => {}
            Type::Txlvote => {}
            Type::Islock => {}
            Type::Isdlock => {}
            Type::Block => {}
            Type::Chainlock => {}
            Type::Headers => {}
            Type::Getaddr => {}
            Type::Mempool => {}
            Type::Ping => {}
            Type::Pong => {}
            Type::Filterload => {}
            Type::Filteradd => {}
            Type::Filterclear => {}
            Type::Merkleblock => {}
            Type::Alert => {}
            Type::Reject => {}
            Type::Sendheaders => {}
            Type::Feefilter => {}
            Type::Senddsq => {}
            Type::Sendcmpct => {}
            Type::Sendaddrv2 => {}
            Type::Spork => {}
            Type::GetSporks => {}
            Type::Dseg => {}
            Type::Mnb => {}
            Type::Mnget => {}
            Type::Mnp => {}
            Type::Mnv => {}
            Type::Mnw => {}
            Type::Mnwb => {}
            Type::Ssc => {}
            Type::Getmnlistd => {}
            Type::Mnlistdiff => {}
            Type::Qrinfo => {}
            Type::Getqrinfo => {}
            Type::Govobj => {}
            Type::Govobjvote => {}
            Type::Govsync => {}
            Type::DarkSendAnnounce => {}
            Type::DarkSendControl => {}
            Type::DarkSendFinish => {}
            Type::DarkSendInitiate => {}
            Type::DarkSendQuorum => {}
            Type::DarkSendSession => {}
            Type::DarkSendSessionUpdate => {}
            Type::DarkSendTX => {}
        }
    }

    pub fn accept_version_message(&mut self, message: &[u8]) {
        NSNumber *l = nil;
        if message.len() < 85 {
            self.disconnect_with_error(Some(Error::Default(format!("malformed version message, length is {}, should be > 84", message.len()))));
            return;
        }
        let offset = &mut 0;
        self.version = message.read_with::<u32>(offset, byte::LE).unwrap();
        self.services = message.read_with::<u64>(offset, byte::LE).unwrap();
        self.timestamp = message.read_with::<u64>(offset, byte::LE).unwrap();
        let useragent_len = message.read_with::<VarInt>(offset, byte::LE).unwrap().0 as usize;
        self.useragent = message.read_with::<&str>(offset, Str::Len(useragent_len)).unwrap().to_string();
        if message.len() < 80 + *offset + std::mem::size_of::<u32>() {
            self.disconnect_with_error(Some(Error::Default(format!("malformed version message, length is {}, should be {}", message.len(), 80 + useragent_len + 4))));
            return;
        }
        self.last_block_height = message.read_with::<u32>(offset, byte::LE).unwrap();
        if self.version < self.chain.params.min_protocol_version {
            self.disconnect_with_error(Some(Error::Default(format!("protocol version {} not supported", self.version))));
            return;
        }
        self.send_verack_message();
    }

    pub fn accept_verack_message(&mut self, message: &[u8]) {
        if self.got_verack {
            println!("{}:{} got unexpected verack", self.host(), self.port);
        } else {
            // use verack time as initial ping time
            self.ping_time = SystemTime::seconds_since_1970() - self.ping_start_time;
            self.ping_start_time = 0;
            self.got_verack = true;
            self.did_connect();
        }
    }

    /// TODO: relay addresses
    pub fn accept_addr_message(&mut self, message: &[u8]) {
        if message.len() > 0 && message.read_with::<u8>(&mut 0, byte::LE).unwrap() == 0 {
            println!("{}:{} got addr with 0 addresses", self.host(), self.port);
            return;
        } else if message.len() < 5 {
            self.disconnect_with_error(Some(Error::Default(format!("malformed addr message, length {} is too short", message.len()))));
            return;
        } else if !self.sent_getaddr {
            return; // simple anti-tarpitting tactic, don't accept unsolicited addresses
        }
        let now = SystemTime::seconds_since_1970();

        let offset = &mut 0;
        let count = message.read_with::<VarInt>(offset, byte::LE).unwrap();
        let size = count.len() + count.0 * 30;
        if count.0 > 1000 {
            println!("{}:{} dropping addr message, {} is too many addresses (max 1000)", self.host(), self.port, count);
            return;
        } else if message.len() < size {
            self.disconnect_with_error(Some(Error::Default(format!("malformed addr message, length is {}, should be {} for {} addresses", message.len(), size, count.0))));
            return;
        } else {
            println!("{}:{} got addr with {} addresses", self.host(), self.port, count.0);
        }
        let mut peers = Vec::<Peer>::new();
        (count.len()..size).step_by(30).for_each(|mut off| {
            let mut timestamp = message.read_with::<u32>(&mut off, byte::LE).unwrap() as u64;
            let services = message.read_with::<u64>(&mut off, byte::LE).unwrap();
            let address = message.read_with::<UInt128>(&mut off, byte::LE).unwrap();
            let port = message.read_with::<u16>(&mut off, byte::LE).unwrap();
            if services & SERVICES_NODE_NETWORK != 0 && IpAddr::from(address.0).is_ipv4() {
                // if address time is more than 10 min in the future or older than reference date, set to 5 days old
                if timestamp > now + 10 * 60 || timestamp < 0 {
                    timestamp = now - 5 * 24 * 60 * 60;
                }
                peers.push(Peer::init_with_address(address, port, self.chain, timestamp - 2 * 60 * 60, services));

            } else {
                // skip peers that don't carry full blocks
                // ignore IPv6 for now
            }
        });
        todo!()
        //dispatch_async(self.delegateQueue, ^{
        // if self.status() == PeerStatus::Connected {
        //     [self.peerDelegate peer:self relayedPeers:peers]
        // }
        //});
    }

    pub fn accept_addrv2_message(&self, message: &[u8]) {
        println!("{}:{} sendaddrv2, len:{}, (not implemented)", self.host(), self.port, message.len());
    }

    pub fn accept_inv_message(&mut self, message: &[u8]) {
        let offset = &mut 0;
        let count = message.read_with::<VarInt>(offset, byte::LE).unwrap();
        if count.len() == 0 || message.len() < count.len() + count.0 * 36 {
            self.disconnect_with_error(Some(Error::Default(format!("malformed inv message, length is {}, should be {} for {} items", message.len(), if count.len() == 0 { 1 } else { count.len() + count.0 * 36}, count.0))));
            return;
        } else if count.0 > MAX_GETDATA_HASHES as u64 {
            println!("{}:{} dropping inv message, {} is too many items, max is {}", self.host(), self.port, count.0, MAX_GETDATA_HASHES);
            return;
        }
        let mut tx_hashes = Vec::<UInt256>::new();
        let mut is_lock_hashes = Vec::<UInt256>::new();
        let mut isd_lock_hashes = Vec::<UInt256>::new();
        let mut c_lock_hashes = Vec::<UInt256>::new();
        let mut block_hashes = Vec::<UInt256>::new();
        let mut spork_hashes = Vec::<UInt256>::new();
        let mut governance_object_hashes = Vec::<UInt256>::new();
        let mut governance_object_vote_hashes = Vec::<UInt256>::new();
        let mut only_private_send_transactions = false;
        (count.len()..count.len() + 36 * count.0)
            .step_by(36)
            .for_each(|mut off| {
            let r#type = message.read_with::<InvType>(&mut off, byte::LE).unwrap();
            let hash = message.read_with::<UInt256>(&mut off, byte::LE).unwrap();
            if !hash.is_zero() {
                if r#type != InvType::Tx {
                    only_private_send_transactions = false;
                } else if off == count.len() {
                    only_private_send_transactions = true;
                }
                match r#type {
                    InvType::Tx |
                    InvType::TxLockRequest => { tx_hashes.push(hash); },
                    InvType::Block |
                    InvType::Merkleblock => { block_hashes.push(hash); },
                    InvType::InstantSendLock => { is_lock_hashes.push(hash); },
                    InvType::InstantSendDeterministicLock => { isd_lock_hashes.push(hash); },
                    InvType::Spork => { spork_hashes.push(hash); },
                    InvType::GovernanceObject => { governance_object_hashes.push(hash); },
                    InvType::ChainLockSignature => { c_lock_hashes.push(hash); },
                    InvType::DSTx |
                    InvType::TxLockVote |
                    InvType::MasternodePing |
                    InvType::MasternodeVerify |
                    InvType::MasternodeBroadcast |
                    InvType::QuorumFinalCommitment |
                    InvType::DummyCommitment |
                    InvType::QuorumContribution |
                    InvType::CompactBlock |
                    InvType::QuorumPrematureCommitment |
                    InvType::GovernanceObjectVote |
                    InvType::MasternodePaymentVote => {},
                    _ => {
                        assert!(false, format!("inventory type not dealt with: {}", r#type.into()));
                    }
                }
            }
        });

        if self.chain.syncs_blockchain() && !self.sent_filter && !self.sent_mempool && !self.sent_getblocks && !tx_hashes.is_empty() && !only_private_send_transactions {
            self.disconnect_with_error(Some(Error::Default(format!("got tx inv message before loading a filter"))));
            return;
        } else if tx_hashes.len() + is_lock_hashes.len() + isd_lock_hashes.len() > 10000 {
            // this was happening on testnet, some sort of DOS/spam attack?
            println!("{}:{} too many transactions, disconnecting", self.host(), self.port);
            // disconnecting seems to be the easiest way to mitigate it
            self.disconnect();
            return;
        } else if self.current_block_height > 0 &&
            block_hashes.len() > 2 &&
            block_hashes.len() < 500 &&
            self.current_block_height + self.known_block_hashes.len() + block_hashes.len() < self.last_block_height {
            self.disconnect_with_error(Some(Error::Default(format!("non-standard inv, {} is fewer block hashes than expected", block_hashes.len()))));
            return;
        }

        if block_hashes.len() == 1 && self.last_block_hash.eq(&block_hashes[0]) {
            block_hashes.clear();
        }
        if block_hashes.len() == 1 {
            self.last_block_hash = block_hashes[0];
        }
        if !block_hashes.is_empty() {
            // remember blockHashes in case we need to re-request them with an updated bloom filter
            self.delegate_context.queue(|| {
                self.known_block_hashes = HashSet::from(&self.known_block_hashes).union(&HashSet::from(&block_hashes)).collect();
                while self.known_block_hashes.len() < MAX_GETDATA_HASHES {
                    self.known_block_hashes.drain(0..self.known_block_hashes.len() / 3);
                }
            });
        }
        let known_tx_hashes_set = HashSet::from(&self.known_tx_hashes);
        tx_hashes.intersection(&known_tx_hashes_set).for_each(|hash| {
            self.delegate_context.queue(|| {
                if self.status() == PeerStatus::Connected {
                    self.transaction_delegate.peer_has_transaction_with_hash(self, hash);
                }
            });
        });
        tx_hashes = tx_hashes.difference(&known_tx_hashes_set).collect().iter().collect();
        self.known_tx_hashes = known_tx_hashes_set.union(&tx_hashes).collect().iter().collect();

        if !is_lock_hashes.is_empty() {
            let known_is_lock_hashes_set = HashSet::from(&self.known_is_lock_hashes);
            is_lock_hashes = is_lock_hashes.difference(&known_is_lock_hashes_set).collect().iter().collect();
            //dispatch_async(self.delegateQueue, ^{
            if self.status() == PeerStatus::Connected {
                self.transaction_delegate.peer_has_instant_send_lock_hashes(self, is_lock_hashes);
            }
            //});
            self.known_is_lock_hashes = known_is_lock_hashes_set.union(&is_lock_hashes).collect().iter().collect();
        }

        if !isd_lock_hashes.is_empty() {
            let known_isd_lock_hashes_set = HashSet::from(&self.known_isd_lock_hashes);
            isd_lock_hashes = isd_lock_hashes.difference(&known_isd_lock_hashes_set).collect().iter().collect();
            //dispatch_async(self.delegateQueue, ^{
            if self.status() == PeerStatus::Connected {
                self.transaction_delegate.peer_has_instant_send_deterministic_lock_hashes(self, isd_lock_hashes);
            }
            //});
            self.known_isd_lock_hashes = known_isd_lock_hashes_set.union(&isd_lock_hashes).collect().iter().collect();
        }

        if !c_lock_hashes.is_empty() {
            let known_c_lock_hashes_set = HashSet::from(&self.known_chain_lock_hashes);
            c_lock_hashes = c_lock_hashes.difference(&known_c_lock_hashes_set).collect().iter().collect();
            //dispatch_async(self.delegateQueue, ^{
            if self.status() == PeerStatus::Connected {
                self.transaction_delegate.peer_has_chain_lock_hashes(self, c_lock_hashes);
            }
            //});
            self.known_chain_lock_hashes = known_c_lock_hashes_set.union(&c_lock_hashes).collect().iter().collect();
        }

        if tx_hashes.len() + is_lock_hashes.len() + isd_lock_hashes.len() > 0 ||
            (!self.needs_filter_update && (block_hashes.len() + c_lock_hashes.len() > 0)) {
            self.send_getdata_message_with_tx_hashes(
                Some(tx_hashes.iter().collect()),
                Some(is_lock_hashes.iter().collect()),
                Some(isd_lock_hashes.iter().collect()),
                if self.needs_filter_update { None } else { Some(block_hashes.iter().collect()) },
                Some(c_lock_hashes.iter().collect()),
            );
        }

        // to improve chain download performance, if we received 500 block hashes, we request the next 500 block hashes
        if !self.needs_filter_update {
            if block_hashes.len() >= 500 {
                let locators = vec![block_hashes[block_hashes.len() - 1], block_hashes[0]];
                if self.chain.should_request_merkle_blocks_for_zone_after_height(self.chain.last_sync_block_height + 1) {
                    self.send_getblocks_message_with_locators(locators, UInt256::MIN);
                } else {
                    self.send_getheaders_message_with_locators(locators, UInt256::MIN);
                }
            } else if block_hashes.len() >= 2 && self.chain.sync_phase == ChainSyncPhase::ChainSync {
                let mut found_last_hash = false;
                let last_terminal_block_hash = self.chain.last_terminal_block.unwrap().block_hash();
                for block_hash in block_hashes {
                    if block_hash == last_terminal_block_hash {
                        found_last_hash = true;
                    }
                }
                if !found_last_hash {
                    // we did not find the last hash, lets ask the remote again for blocks as a race condition might have occured
                    self.send_getblocks_message_with_locators(vec![block_hashes[block_hashes.len() - 1], block_hashes[0]], UInt256::MIN);
                }
            } else if block_hashes.len() == 1 && self.chain.sync_phase == ChainSyncPhase::ChainSync {
                // this could either be a terminal block, or very rarely (1 in 500) the race condition dealt with above but block hashes being 1
                // First we ust find if the blockHash is a terminal block hash
                //
                let found_in_terminal_blocks = self.chain.terminal_blocks.get(block_hashes.first().unwrap()).is_some();
                let is_last_terminal_block = self.chain.last_terminal_block.unwrap() == block_hashes.first().unwrap();

                if found_in_terminal_blocks && !is_last_terminal_block {
                    self.send_getblocks_message_with_locators(vec![block_hashes[block_hashes.len() - 1], block_hashes[0]], UInt256::MIN);
                }
            }
        }

        if self.mempool_transaction_callback.is_some() && (tx_hashes.len() + governance_object_hashes.len() + spork_hashes.len() > 0) {
            // this will cancel the mempool timeout
            self.mempool_request_time = SystemTime::seconds_since_1970();
            println!("[DSPeer] got mempool tx inv messages {}", self.host());
            let completion = self.mempool_transaction_callback.unwrap();
            self.send_ping_message(|success| {
                completion(success, true, false);
            });
            self.mempool_transaction_callback = None;
        }

        if !governance_object_hashes.is_empty() {
            self.governance_delegate.peer_has_governance_object_hashes(self, governance_object_hashes);
        }
        if !governance_object_vote_hashes.is_empty() {
            self.governance_delegate.peer_has_governance_vote_hashes(self, governance_object_vote_hashes);
        }
        if !spork_hashes.is_empty() {
            self.spork_delegate.peer_has_spork_hashes(self, spork_hashes);
        }
    }

    pub fn accept_tx_message(&mut self, message: &[u8]) {
        let tx = tx::Factory::transaction_with_message(message, self.chain);
        if tx.is_none() && !tx::Factory::should_ignore_transaction_message(message) {
            self.disconnect_with_error(Some(Error::Default(format!("malformed tx message: {:?}", message))));
            return;
        } else if !self.sent_filter && !self.sent_getdatatxblocks {
            self.disconnect_with_error(Some(Error::Default(format!("got tx message before loading a filter"))));
            return;
        }

        if let Some(tx) = tx {
            let current_block = self.current_block;
            //dispatch_async(self.delegateQueue, ^{
            self.transaction_delegate.peer_relayed_transaction(self, &tx, current_block);
            //});
        }

        if let Some(c_block) = self.current_block {
            // we're collecting tx messages for a merkleblock
            let tx_hash = if let Some(tx) = &tx {
                tx.tx_hash()
            } else {
                UInt256::sha256d(message)
            };
            if let Some(mut block_tx_hashes) = &self.current_block_tx_hashes {
                if let Some(pos) = block_tx_hashes.iter().position(|x| x == &tx_hash) {
                    block_tx_hashes.remove(pos);
                }
                if block_tx_hashes.is_empty() {
                    // we received the entire block including all matched tx
                    println!("{}:{} clearing current block", self.host(), self.port);
                    self.current_block = None;
                    self.current_block_tx_hashes = None;
                    //dispatch_sync(self.delegateQueue, ^{ // syncronous dispatch so we don't get too many queued up tx
                    self.transaction_delegate.peer_relayed_block(self, &c_block);
                    //});
                }
            }
        } else {
            println!("{}:{} no current block", self.host(), self.port);
        }
    }

    fn accept_islock_message(&mut self, message: &[u8]) {
        if !self.chain.spork_manager().deterministic_masternode_list_enabled {
            println!("returned instant send lock message when DML not enabled: {:?}", message); //no error here
            return;
        } else if !self.chain.spork_manager().llmq_instant_send_enabled {
            println!("returned instant send lock message when llmq instant send is not enabled: {:?}", message); //no error here
            return;
        }
        if let Some(is_tx_lock) = InstantSendTransactionLock::init_with_message(message, false, self.chain) {
            if !self.sent_filter && !self.sent_getdatatxblocks {
                self.disconnect_with_error(Some(Error::Default(format!("got islock message before loading a filter"))));
                return;
            }
            // TODO: impl async
            //dispatch_async(self.delegateQueue, ^{
            self.transaction_delegate.peer_relayed_instant_send_transaction_lock(self, is_tx_lock);
            //});

        } else {
            self.disconnect_with_error(Some(Error::Default(format!("malformed islock message: {:?}", message))));
            return;
        }
    }

    fn accept_isdlock_message(&mut self, message: &[u8]) {
        if !self.chain.spork_manager().deterministic_masternode_list_enabled {
            println!("returned instant send lock message when DML not enabled: {:?}", message); //no error here
            return;
        } else if !self.chain.spork_manager().llmq_instant_send_enabled {
            println!("returned instant send lock message when llmq instant send is not enabled: {:?}", message); //no error here
            return;
        }
        if let Some(isd_tx_lock) = InstantSendTransactionLock::init_with_message(message, true, self.chain) {
            if !self.sent_filter && !self.sent_getdatatxblocks {
                self.disconnect_with_error(Some(Error::Default(format!("got isdlock message before loading a filter"))));
                return;
            }
            // TODO: impl async
            //dispatch_async(self.delegateQueue, ^{
            self.transaction_delegate.peer_relayed_instant_send_transaction_lock(self, isd_tx_lock);
            //});
        } else {
            self.disconnect_with_error(Some(Error::Default(format!("malformed isdlock message: {:?}", message))));
            return;
        }
    }

    // HEADER FORMAT:
    // 01 ................................. Header count: 1
    //
    // 02000000 ........................... Block version: 2
    // b6ff0b1b1680a2862a30ca44d346d9e8
    // 910d334beb48ca0c0000000000000000 ... Hash of previous block's header
    // 9d10aa52ee949386ca9385695f04ede2
    // 70dda20810decd12bc9b048aaab31471 ... Merkle root
    // 24d95a54 ........................... Unix time: 1415239972
    // 30c31b18 ........................... Target (bits)
    // fe9f0864 ........................... Nonce
    //
    // 00 ................................. Transaction count (0x00)
    pub fn accept_headers_message(&mut self, message: &[u8]) {
        let offset = &mut 0;
        let count = message.read_with::<VarInt>(offset, byte::LE).unwrap();
        let num_headers = count.0;
        let expected_size = count.len() + 81 * num_headers;
        if message.len() < expected_size {
            self.disconnect_with_error(Some(Error::Default(format!("malformed headers message, length is {}, should be {} for {} items", message.len(), expected_size, num_headers))));
            return;
        }
        if self.relay_start_time != 0 {
            // keep track of relay performance
            let speed = num_headers / (SystemTime::seconds_since_1970() - self.relay_start_time);

            if self.relay_speed == 0 {
                self.relay_speed = speed;
            }
            self.relay_speed = self.relay_speed * 0.9 + speed * 0.1;
            self.relay_start_time = 0;
        }

        // To improve chain download performance, if this message contains 2000 headers then request the next 2000 headers
        // immediately, and switch to requesting blocks when we receive a header newer than earliestKeyTime
        // Devnets can run slower than usual
        // TODO: check reading offset
        let last_timestamp = message.read_with::<u32>(offset, byte::LE).unwrap() as u64;
        let first_timestamp = message.read_with::<u32>(offset, byte::LE).unwrap() as u64;
        // NSTimeInterval lastTimestamp = [message UInt32AtOffset:l + 81 * (count - 1) + 68];
        // NSTimeInterval firstTimestamp = [message UInt32AtOffset:l + 81 + 68];
        if !self.chain.needs_initial_terminal_headers_sync() &&
            (first_timestamp + DAY_TIME_INTERVAL * 2 >= self.earliestKeyTime) &&
            self.chain.should_request_merkle_blocks_for_zone_after_height(self.chain.last_sync_block_height + 1) {
            // this is a rare scenario where we called getheaders but the first header returned was actually past the cuttoff, but the previous header was before the cuttoff
            println!("{}:{} calling getblocks with locators: {:?}", self.host(), self.port, self.chain.chain_sync_block_locator_array());
            self.send_getblocks_message_with_locators(self.chain.chain_sync_block_locator_array(), UInt256::MIN);
            return;
        }
        if num_headers == 0 {
            return;
        }
        if num_headers >= self.chain.params.headers_max_amount as u64 || (((last_timestamp + DAY_TIME_INTERVAL * 2) >= self.earliest_key_time) && (!self.chain.needs_initial_terminal_headers_sync())) {
            let mut first_block_hash = x11_hash(bytes.read_with(offset, Bytes::Len(80)).unwrap());
            let last_offset = &mut (*offset) + 81 * (num_headers - 1);
            let mut last_block_hash = x11_hash(bytes.read_with(last_offset, Bytes::Len(80)).unwrap());
            if last_timestamp + DAY_TIME_INTERVAL * 2 >= self.earliest_key_time &&
                !self.chain.needs_initial_terminal_headers_sync() &&
                self.chain.should_request_merkle_blocks_for_zone_after_height(self.chain.last_sync_block_height + 1) {
                // request blocks for the remainder of the chain
                //NSTimeInterval timestamp = [message UInt32AtOffset:l + 81 + 68];
                let mut timestamp = message.read_with::<u32>(offset, byte::LE).unwrap() as u64;
                // for (off = l; timestamp > 0 && ((timestamp + DAY_TIME_INTERVAL * 2) < self.earliestKeyTime);) {
                //     off += 81;
                //     timestamp = [message UInt32AtOffset:off + 81 + 68];
                // }
                let off = &mut *offset;
                while timestamp > 0 && (timestamp + DAY_TIME_INTERVAL * 2 < self.earliest_key_time) {
                    timestamp = message.read_with::<u32>(off, byte::LE).unwrap() as u64;
                }
                last_block_hash = x11_hash(bytes.read_with(off, Bytes::Len(80)).unwrap());
                println!("{}:{} calling getblocks with locators: [{}, {}]", self.host(), self.port, last_block_hash, first_block_hash);
                self.send_getblocks_message_with_locators(vec![last_block_hash, first_block_hash], UInt256::MIN);
            } else {
                println!("{}:{} calling getheaders with locators: [{}, {}]", self.host(), self.port, last_block_hash, first_block_hash);
                self.send_getheaders_message_with_locators(vec![last_block_hash, first_block_hash], UInt256::MIN);
            }
        }

        let mut iter: Iter<&[u8], _> = message.read_iter(offset, Bytes::Len(81));
        while let Some(data) = iter.next() {
            let block = MerkleBlock::init_with_message(data, self.chain).unwrap();
            if !block.is_valid() {
                self.disconnect_with_error(Some(Error::Default(format!("invalid block header {}", block.block_hash()))));
                return;
            }
            //dispatch_async(self.delegateQueue, ^{
            self.transaction_delegate.peer_relayed_header(self, &block);
            //});
        }
    }

    pub fn accept_getaddr_message(&self, _message: &[u8]) {
        println!("{}:{} got getaddr", self.host(), self.port);
        self.send_request(Request::Addr);
    }

    pub fn accept_getdata_message(&mut self, message: &[u8]) {
        let offset = &mut 0;
        let count = message.read_with::<VarInt>(offset, byte::LE).unwrap();
        let l = count.len();
        let size = count.0;
        if l == 0 || message.len() < l + size * 36 {
            self.disconnect_with_error(Some(Error::Default(format!("malformed getdata message, length is {}, should be {} for {} items", message.len(), if l == 0 { 1 } else { l } + size * 36, size))));
            return;
        } else if size > MAX_GETDATA_HASHES as u64 {
            println!("{}:{} dropping getdata message, {} is too many items, max is {}", self.host(), self.port, size, MAX_GETDATA_HASHES);
            return;
        }
        println!("{}:{} {}got getdata for {} item{}", self.host(), self.port, if self.peer_delegate.download_peer == self { "(download peer)" } else { "" }, size, if size == 1 { "" } else { "s" });
        //dispatch_async(self.delegateQueue, ^{
        let mut notfound = Vec::<u8>::new();
        let mut iter: Iter<&[u8], _> = message.read_iter(offset, Bytes::Len(36));
        while let Some(data) = iter.next() {
            let r#type = data.read_with::<InvType>(offset, byte::LE).unwrap();
            let hash = data.read_with::<UInt256>(offset, byte::LE).unwrap();
            if hash.is_zero() {
                continue;
            }
            match r#type {
                InvType::Tx |
                InvType::TxLockRequest => {
                    if let Some(transaction) = self.transaction_delegate.peer_requested_transaction(self, &hash) {
                        self.send_message(transaction.to_data(), Type::Tx);
                    } else {
                        r#type.enc(&mut notfound);
                        hash.enc(&mut notfound);
                    }
                },
                InvType::GovernanceObjectVote => {
                    if let Some(vote) = self.governance_delegate.peer_requested_vote(self, &hash) {
                        self.send_message(vote.data_message(), Type::Govobjvote);
                    } else {
                        r#type.enc(&mut notfound);
                        hash.enc(&mut notfound);
                    }
                },
                InvType::GovernanceObject => {
                    if let Some(object) = self.governance_delegate.peer_requested_object(self, &hash) {
                        self.send_message(object.data_message(), Type::Govobj);
                    } else {
                        r#type.enc(&mut notfound);
                        hash.enc(&mut notfound);
                    }
                },
                _ => {
                    r#type.enc(&mut notfound);
                    hash.enc(&mut notfound);
                }

            }
        }
        if !notfound.is_empty() {
            self.send_request(Request::NotFound(notfound));
        }
        //});
    }

    pub fn accept_notfound_message(&mut self, message: &[u8]) {
        let offset = &mut 0;
        let count = message.read_with::<VarInt>(offset, byte::LE).unwrap();
        let l = count.len();
        let size = count.0;
        if l == 0 || message.len() < l + size * 36 {
            self.disconnect_with_error(Some(Error::Default(format!("malformed notfound message, length is {}, should be {} for {} items", message.len(), if l == 0 { 1 } else { l } + size * 36, size))));
            return;
        }
        println!("{}:{} got notfound with {} item{}", self.host(), self.port, size, if size == 1 { "" } else { "s" });
        let mut tx_hashes = Vec::<UInt256>::new();
        let mut tx_lock_request_hashes = Vec::<UInt256>::new();
        let mut block_hashes = Vec::<UInt256>::new();
        let mut iter: Iter<&[u8], _> = message.read_iter(offset, Bytes::Len(36));
        while let Some(data) = iter.next() {
            match data.read_with::<InvType>(offset, byte::LE) {
                Ok(InvType::Tx) => {
                    tx_hashes.push(data.read_with::<UInt256>(offset, byte::LE).unwrap());
                },
                Ok(InvType::TxLockRequest) => {
                    tx_lock_request_hashes.push(data.read_with::<UInt256>(offset, byte::LE).unwrap());
                },
                Ok(InvType::Merkleblock) => {
                    block_hashes.push(data.read_with::<UInt256>(offset, byte::LE).unwrap());
                },
                Err(..) => {}
            }
        }
        //dispatch_async(self.delegateQueue, ^{
        self.transaction_delegate.peer_relayed_not_found_messages_with_transaction_hashes(self, tx_hashes, block_hashes);
        //});
    }

    pub fn accept_ping_message(&mut self, message: &[u8]) {
        if message.len() < std::mem::size_of::<u64>() {
            self.disconnect_with_error(Some(Error::Default(format!("malformed ping message, length is {}, should be 4", message.len()))));
            return;
        }
        self.send_message(message.to_vec(), Type::Pong);
    }

    pub fn accept_pong_message(&mut self, message: &[u8]) {
        if message.len() < std::mem::size_of::<u64>() {
            self.disconnect_with_error(Some(Error::Default(format!("malformed pong message, length is {}, should be 4", message.len()))));
            return;
        } else if message.read_with::<u64>(&mut 0, byte::LE).unwrap() != self.local_nonce {
            self.disconnect_with_error(Some(Error::Default(format!("pong message contained wrong nonce: {}, expected: {}", message.read_with::<u64>(&mut 0, byte::LE).unwrap(), self.local_nonce))));
            return;
        } else if self.pong_handlers.is_empty() {
            println!("{}:{} got unexpected pong", self.host(), self.port);
            return;
        }
        if self.ping_start_time > 1 {
            let ping_time = SystemTime::seconds_since_1970() - self.ping_start_time;
            // 50% low pass filter on current ping time
            self.ping_time = 0.5 * (self.ping_time + ping_time);
            self.ping_start_time = 0;
        }
        //dispatch_async(self.delegateQueue, ^{
        if self.status() == PeerStatus::Connected && !self.pong_handlers.is_empty() {
            if let Some(handler) = self.pong_handlers.first() {
                handler(true);
                self.pong_handlers.remove(0);
            }
        }
        //});
    }

    // Dash nodes don't support querying arbitrary transactions, only transactions not yet accepted in a block.
    // After a merkleblock message, the remote node is expected to send tx messages for the tx referenced in the block.
    // When a non-tx message is received we should have all the tx in the merkleblock.
    pub fn accept_merkleblock_message(&mut self, message: &[u8]) {
        if let Some(block) = MerkleBlock::init_with_message(message, self.chain) {
            if !block.is_valid() {
                self.disconnect_with_error(Some(Error::Default(format!("invalid merkleblock: {}", block.block_hash()))));
                return;
            } else if !self.sent_filter && !self.sent_getdatatxblocks {
                self.disconnect_with_error(Some(Error::Default(format!("got merkleblock message before loading a filter"))));
                return;
            }
            let mut tx_hashes = HashSet::from(&block.transaction_hashes());
            let known_tx_hashes_set = HashSet::from(&self.known_tx_hashes);
            tx_hashes = tx_hashes.difference(&known_tx_hashes_set).collect().iter().collect();
            if !tx_hashes.is_empty() {
                // wait til we get all the tx messages before processing the block
                self.current_block = Some(block);
                self.current_block_tx_hashes = Some(tx_hashes.collect_vec());
            } else {
                //dispatch_async(self.delegateQueue, ^{
                self.transaction_delegate.peer_relayed_block(self, &block);
                //});
            }
        }
    }

    /// DIP08: https://github.com/dashpay/dips/blob/master/dip-0008.md
    pub fn accept_chain_lock_message(&mut self, message: &[u8]) {
        if !self.chain.spork_manager().chain_locks_enabled {
            return;
        }
        if let Some(chain_lock) = ChainLock::init_with_message(message, self.chain) {
            if !self.sent_filter && !self.sent_getdatatxblocks {
                self.disconnect_with_error(Some(Error::Default(format!("got chain lock message before loading a filter"))));
            } else {
                //dispatch_async(self.delegateQueue, ^{
                self.transaction_delegate.peer_relayed_chain_lock(self, &chain_lock);
                //});
            }
        } else {
            self.disconnect_with_error(Some(Error::Default(format!("malformed chain lock message: {:?}", message))));
        }
    }

    /// BIP61: https://github.com/bitcoin/bips/blob/master/bip-0061.mediawiki
    pub fn accept_reject_message(&mut self, message: &[u8]) {
        let offset = &mut 0;
        let r#type = message.read_with::<Type>(offset, byte::LE).unwrap();
        let code = message.read_with::<u8>(offset, byte::LE).unwrap();
        let _reason = message.read_with::<&str>(offset, Str::Delimiter(NULL)).unwrap();
        if r#type == Type::Tx || r#type == Type::Ix {
            let tx_hash = message.read_with::<UInt256>(offset, byte::LE).unwrap();
            if !tx_hash.is_zero() {
                // dispatch_async(self.delegateQueue, ^{
                self.transaction_delegate.peer_rejected_transaction(self, &tx_hash, code);
                // });
            }
        }
    }

    /// BIP133: https://github.com/bitcoin/bips/blob/master/bip-0133.mediawiki
    pub fn accept_fee_filter_message(&mut self, message: &[u8]) {
        if message.len() < std::mem::size_of::<u64>() {
            self.disconnect_with_error(Some(Error::Default(format!("malformed freerate message, length is {}, should be 4", message.len()))));
            return;
        }
        let fee = message.read_with::<u64>(&mut 0, byte::LE).unwrap();
        self.fee_per_byte = fee / 1000;
        println!("{}:{} got feefilter with rate {} per Byte", self.host(), self.port, self.fee_per_byte);
        // dispatch_async(self.delegateQueue, ^{
        self.transaction_delegate.peer_set_fee_per_byte(self, self.fee_per_byte);
        //});
    }

    pub fn accept_spork_message(&mut self, message: &[u8]) {
        let spork = Spork::init_from_message(message, self.chain);
        println!("received spork {:?} with message {}", spork.identifier, hex_with_data(message));
        self.spork_delegate.peer_relayed_spork(self, spork);
    }

    pub fn accept_ssc_message(&mut self, message: &[u8]) {
        let sync_count_info = message.read_with::<SyncCountInfo>(&mut 0, byte::LE).unwrap();
        let count = message.read_with::<u32>(&mut 4, byte::LE).unwrap();
        println!("received ssc message {:?} {}", sync_count_info, count);
        match sync_count_info {
            SyncCountInfo::GovernanceObject if self.governance_request_state == GovernanceRequestState::GovernanceObjectHashes => {
                self.governance_request_state = GovernanceRequestState::GovernanceObjectHashesCountReceived;
                self.chain.peer_relayed_sync_info(self, &sync_count_info, count);
            },
            SyncCountInfo::GovernanceObject if self.governance_request_state == GovernanceRequestState::GovernanceObjectHashesReceived => {
                self.governance_request_state = GovernanceRequestState::GovernanceObjects;
                self.chain.peer_relayed_sync_info(self, &sync_count_info, count);
            },
            SyncCountInfo::GovernanceObjectVote if self.governance_request_state == GovernanceRequestState::GovernanceObjectVoteHashes => {
                self.governance_request_state = GovernanceRequestState::GovernanceObjectVoteHashesCountReceived;
                self.chain.peer_relayed_sync_info(self, &sync_count_info, count);
            },
            SyncCountInfo::GovernanceObjectVote if self.governance_request_state == GovernanceRequestState::GovernanceObjectVoteHashesReceived => {
                self.governance_request_state = GovernanceRequestState::GovernanceObjectVotes;
                self.chain.peer_relayed_sync_info(self, &sync_count_info, count);
            },
            SyncCountInfo::MNW | SyncCountInfo::List => {
                self.chain.peer_relayed_sync_info(self, &sync_count_info, count);
            },
            _ => {}
        }
        //ignore when count = 0; (for votes)
    }

    pub fn accept_mnb_message(&self, _message: &[u8]) {
        // deprecated since version 70211
    }

    pub fn accept_mnlistdiff_message(&self, message: &[u8]) {
        self.masternode_delegate.peer_relayed_masternode_diff_message(self, message);
    }

    pub fn accept_qrinfo_message(&self, message: &[u8]) {
        self.masternode_delegate.peer_relayed_quorum_rotation_info_message(self, message);
    }

    // accept Governance
    // https://dash-docs.github.io/en/developer-reference#govobj

    pub fn accept_gov_object_message(&self, message: &[u8]) {
        if let Some(object) = governance::Object::init_with_message(message, self.chain) {
            self.governance_delegate.peer_relayed_governance_object(self, object);
        }
    }

    pub fn accept_gov_object_vote_message(&self, message: &[u8]) {
        if let Some(vote) = governance::Vote::init_with_message(message, self.chain) {
            self.governance_delegate.peer_relayed_governance_vote(self, vote);
        }
    }

    pub fn accept_gov_object_sync_message(&self, message: &[u8]) {
        println!("Gov Object Sync {:?}", message);
    }


    /// Accept Dark send
    pub fn accept_darksend_announce_message(&self, message: &[u8]) {
        println!("Darksend announce {:?}", message);
    }

    pub fn accept_darksend_control_message(&self, message: &[u8]) {
        println!("Darksend control {:?}", message);
    }

    pub fn accept_darksend_finish_message(&self, message: &[u8]) {
        println!("Darksend finish {:?}", message);
    }

    pub fn accept_darksend_initiate_message(&self, message: &[u8]) {
        println!("Darksend initiate {:?}", message);
    }

    pub fn accept_darksend_quorum_message(&self, message: &[u8]) {
        println!("Darksend quorum {:?}", message);
    }

    pub fn accept_darksend_session_message(&self, message: &[u8]) {
        println!("Darksend session {:?}", message);
    }

    pub fn accept_darksend_session_update_message(&self, message: &[u8]) {
        println!("Darksend session update {:?}", message);
    }

    pub fn accept_darksend_transaction_message(&self, message: &[u8]) {
        println!("Darksend transaction {:?}", message);
    }

    /// FNV32-1a hash of the ip address and port number: http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-1a
    pub fn hash(&self) -> u32 {
        let mut hash = FNV32_OFFSET;
        (0..std::mem::size_of::<UInt128>()).for_each(|i| {
            hash = hash ^ self.address.0[i] * FNV32_PRIME;
            // hash ^= self.address.0[i] * FNV32_PRIME;
        });
        hash = (hash ^ ((self.port >> 8) & 0xff)) * FNV32_PRIME;
        hash = (hash ^ (self.port & 0xff)) * FNV32_PRIME;
        hash
    }

    pub fn chain_tip(&self) -> String {
        if let Some(b) = &self.current_block {
            short_hex_string_from(b.block_hash().as_bytes())
        } else {
            "".to_string()
        }
    }

    pub fn save(&self) {
        todo!("PeerEntity save")
    }



    pub fn connect(&mut self) {
        if self.status() != PeerStatus::Disconnected { return; }
        self.status = PeerStatus::Connecting;
        self.ping_time = u64::MAX;
        todo!()
    }

    pub fn disconnect(&mut self) {
        self.disconnect_with_error(None);
    }

    pub fn disconnect_with_error(&mut self, error: Option<peer_manager::Error>) {
        if self.status() == PeerStatus::Disconnected {
            return;
        }
        if let Some(err) = error {
            println!("Disconnected from peer {} ({} protocol {}) with error {}", self.host(), self.useragent, self.version, err.message());
        } else {
            println!("Disconnected from peer {} ({} protocol {}) with no error", self.host(), self.useragent, self.version);
        }

        //[NSObject cancelPreviousPerformRequestsWithTarget:self]; // cancel connect timeout

        self.status = PeerStatus::Disconnected;
        todo!()
    }

    pub fn did_connect(&mut self) {
        if self.status() != PeerStatus::Connecting || !self.sent_verack || !self.got_verack {
            return;
        }

        // println!("{}:{} handshake completed {}", self.host(), self.port, (self.peerDelegate.downloadPeer == self) ? @"(download peer)" : @"");
        //[NSObject cancelPreviousPerformRequestsWithTarget:self]; // cancel pending handshake timeout
        self.status = PeerStatus::Connected;
        self.delegate_context.queue(|| {
            if self.status() == PeerStatus::Connected {
                self.
            }
        });
        // dispatch_async(self.delegateQueue, ^{
        //     if (self->_status == DSPeerStatus_Connected) [self.peerDelegate peerConnected:self];
        // });
        todo!()
    }

    pub fn received_orphan_block(&mut self) {
        self.received_orphan_count += 1;
        if self.received_orphan_count > 9 {
            //after 10 orphans mark this peer as bad by saying we got a bad block
            self.transaction_delegate.peer_relayed_too_many_orphan_blocks(self.received_orphan_count);
        }

    }
}

// two peer objects are equal if they share an ip address and port number
impl PartialEq<Self> for Peer {
    fn eq(&self, other: &Self) -> bool {
        self == other || self.port == other.port && self.address == other.address
    }
}

// Conversion Sqlite
impl Peer {
    pub fn update_values<T, V>(&self) -> Box<dyn EntityUpdates<V>>
        where T: Table,
              V: AsChangeset<Target=T> {
        Box::new((
            peers::timestamp.eq(NaiveDateTime::from_timestamp_opt(self.timestamp as i64, 0)),
            peers::services.eq(self.services as u64),
            peers::misbehaving.eq(self.misbehaving),
            peers::priority.eq(self.priority as i32),
            peers::low_preference_till.eq(self.low_preference_till as i64),
            peers::last_requested_masternode_list.eq(self.last_requested_masternode_list),
            peers::last_requested_governance_sync.eq(self.last_requested_governance_sync),
        ))
    }

    pub fn create_entity(&self, chain_id: i32) -> NewPeerEntity {
        //TODO: store IPv6 addresses
        // if (self.address.u64[0] != 0 || peer.address.u32[2] != CFSwapInt32HostToBig(0xffff)) return nil;
        NewPeerEntity {
            address: self.address.ip_address_to_i32(),
            port: self.port as i16,
            misbehaving: self.misbehaving,
            priority: self.priority as i32,
            services: self.services as i64,
            timestamp: NaiveDateTime::from_timestamp_opt(self.timestamp as i64, 0).unwrap(),
            last_requested_governance_sync:
            if let Some(timestamp) = self.last_requested_governance_sync {
                NaiveDateTime::from_timestamp_opt(timestamp as i64, 0).unwrap()
            } else {
                None
            },
            last_requested_masternode_list:
            if let Some(timestamp) = self.last_requested_governance_sync {
                NaiveDateTime::from_timestamp_opt(timestamp as i64, 0).unwrap()
            } else {
                None
            },
            low_preference_till: NaiveDateTime::from_timestamp_opt(self.low_preference_till as i64, 0).unwrap(),
            chain_id
        }
    }

}
