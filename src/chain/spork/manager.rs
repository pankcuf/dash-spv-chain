use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::time::{Duration, SystemTime};
use crate::crypto::UInt256;
use crate::chain::chain::Chain;
use crate::chain::dispatch_context::DispatchContext;
use crate::chain::spork::{Identifier, Spork};
use crate::chain::network::{Peer, PeerStatus};
use crate::chain::options::sync_type::SyncType;
use crate::notifications::{Notification, NotificationCenter};
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::spork::SporkEntity;
use crate::util::time::TimeUtil;

pub const SPORK_15_MIN_PROTOCOL_VERSION: u32 = 70213;

pub trait PeerSporkDelegate: Send + Sync + Debug {
    fn peer_relayed_spork(&mut self, peer: &mut Peer, spork: Spork);
    fn peer_has_spork_hashes(&mut self, peer: &Peer, hashes: Vec<UInt256>);
}

#[derive(Default)]
pub struct Manager {
    /// this is the time after a successful spork sync, this is not persisted between sessions
    pub last_requested_sporks: u64,
    /// this is the time after a successful spork sync, this is not persisted between sessions
    pub last_synced_sporks: u64,
    /// spork #2
    pub instant_send_active: bool,
    /// spork #15
    pub deterministic_masternode_list_enabled: bool,
    /// spork #17
    pub quorum_dkg_enabled: bool,
    /// spork #19
    pub chain_locks_enabled: bool,
    /// spork #20
    pub llmq_instant_send_enabled: bool,

    pub spork_dictionary: HashMap<Identifier, Spork>,
    pub chain: &'static Chain,
    pub context: &'static ManagedContext,

    spork_hashes_marked_for_retrieval: Vec<&'static UInt256>,
    spork_timer: Option<os_timer::Timer>,
}

impl<'a> Default for &'a Manager {
    fn default() -> Self {
        &Manager::default()
    }
}

impl Debug for Manager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.spork_dictionary.fmt(f)
    }
}

impl PeerSporkDelegate for Manager {
    fn peer_relayed_spork(&mut self, peer: &mut Peer, spork: Spork) {
        if !spork.is_valid {
            self.chain.peer_manager().peer_misbehaving(peer, "Spork is not valid");
            return;
        }
        self.last_synced_sporks = SystemTime::seconds_since_1970();
        let mut updated = false;
        let mut current_spork: Option<&Spork> = self.spork_dictionary.get(&spork.identifier);
        let mut updated_spork: Option<&Spork> = None;
        if let Some(current_spork) = updated_spork {
            // there was already a spork
            if current_spork != &spork {
                // set it to new one
                self.set_spork_value(spork, spork.identifier.clone());
                updated_spork = Some(current_spork);
                updated = true;
            } else {
                // lets check triggers anyways in case of an update of trigger code
                self.check_triggers_for_spork(&spork, &spork.identifier);
                return;
            }
        } else {
            self.set_spork_value(spork, spork.identifier.clone());
        }

        if current_spork.is_none() || updated {
            self.chain.chain_context().perform_block_and_wait(|context| {
                // todo: think maybe it's better to store spork hashes separately
                SporkEntity::update_with_spork(&spork, spork.calculate_spork_hash(), context)
                    .expect("Can't update spork entity");
            });
            DispatchContext::main_context().queue(|| NotificationCenter::post(Notification::SporkListDidUpdate {
                chain: self.chain,
                old: updated_spork,
                new: Some(&spork),
            }));
        }
    }

    fn peer_has_spork_hashes(&mut self, peer: &Peer, hashes: Vec<UInt256>) {
        let marked = hashes.iter().filter_map(|hash|
            if !self.spork_hashes_marked_for_retrieval.contains(&hash) {
                Some(hash) }
            else {
                None
            })
            .collect::<Vec<_>>();
        self.spork_hashes_marked_for_retrieval.extend(marked);
        if !marked.is_empty() {
            self.get_sporks();
        }
    }
}

impl Manager {

    pub fn new(chain: &Chain) -> Self {
        let mut s = Self { chain, context: chain.chain_context(), ..Default::default() };
        s.load_in_context(&s.context);
        s
    }

    fn load_in_context(&mut self, context: &ManagedContext) {
        // todo: check this out
        self.context.perform_block_and_wait(|context| {
            match SporkEntity::get_all_for_chain_type(self.chain.r#type(), context) {
                Ok(entities) => {
                    let (spork_dictionary, spork_hashes_marked_for_retrieval) = entities.iter().fold((HashMap::new(), Vec::new()), |(mut dict, mut hashes), entity| {
                        if entity.marked_for_retrieval > 0 {
                            hashes.push(&entity.spork_hash);
                        } else {
                            dict.insert(Identifier::from(entity.identifier), Spork::from_entity(&entity, self.chain));
                        }
                        (dict, hashes)
                    });
                    self.spork_dictionary = spork_dictionary;
                    self.spork_hashes_marked_for_retrieval = spork_hashes_marked_for_retrieval;
                    self.check_triggers();
                },
                Err(err) => println!("Error retrieving sporks for chain {:?}", self.chain.r#type())
            }
        });
    }
}

impl Manager {
    pub fn instant_send_active(&mut self) -> bool {
        self.spork_dictionary
            .get(&Identifier::Spork2InstantSendEnabled)
            .map_or(true,|mut s| s.feature_is_activated())
    }

    pub fn sporks_updated_signatures(&mut self) -> bool {
        self.spork_dictionary
            .get(&Identifier::Spork6NewSigs)
            .map_or(false, |mut s| s.feature_is_activated())
    }

    pub fn deterministic_masternode_list_enabled(&mut self) -> bool {
        self.spork_dictionary
            .get(&Identifier::Spork15DeterministicMasternodesEnabled)
            .map_or(true, |mut s| s.feature_is_activated())
    }

    pub fn llmq_instant_send_enabled(&mut self) -> bool {
        self.spork_dictionary
            .get(&Identifier::Spork20InstantSendLLMQBased)
            .map_or(true, |mut s| s.feature_is_activated())
    }

    pub fn quorum_dkg_enabled(&mut self) -> bool {
        self.spork_dictionary
            .get(&Identifier::Spork17QuorumDKGEnabled)
            .map_or(true, |mut s| s.feature_is_activated())
    }

    pub fn chain_locks_enabled(&mut self) -> bool {
        self.spork_dictionary
            .get(&Identifier::Spork19ChainLocksEnabled)
            .map_or(true, |mut s| s.feature_is_activated())
    }
}

impl Manager {

    /// Spork Sync

    pub fn perform_spork_request(&mut self) {
        // after syncing, get sporks from other peers
        self.chain.peer_manager().connected_peers.iter().for_each(|mut p| {
            if p.status == PeerStatus::Connected {
                p.send_ping_message(|success| {
                    if success {
                        self.last_requested_sporks = SystemTime::seconds_since_1970();
                        p.send_get_sporks();
                    }
                });
            }
        });
    }


    pub fn get_sporks(&mut self) {
        if !self.chain.options.sync_type.contains(SyncType::Sporks) {
            // make sure we care about sporks
            return;
        } else if self.spork_timer.is_none() {

            let timer = os_timer::Timer::new(os_timer::Callback::closure(|| {
                // wait 10 minutes between requests
                if self.last_synced_sporks < SystemTime::ten_minutes_ago_1970() {
                    self.perform_spork_request();
                }
            }));
            self.spork_timer = timer;
            if let Some(timer) = &timer {
                timer.schedule_interval(Duration::ZERO, Duration::from_secs(600));
            }
        }
    }

    pub fn stop_getting_sporks(&mut self) {
        if self.spork_timer.is_some() {
            self.spork_timer = Some(unsafe {
                os_timer::Timer::uninit()
            });
        }
    }

    pub fn check_triggers(&mut self) {
        self.spork_dictionary.values()
            .for_each(|spork| self.check_triggers_for_spork(spork, &spork.identifier))
    }

    pub fn check_triggers_for_spork(&mut self, spork: &Spork, identifier: &Identifier) {
        let mut changed = false;
        if !self.spork_dictionary.contains_key(identifier) ||
            (self.spork_dictionary.contains_key(identifier) &&
                self.spork_dictionary[identifier].value != spork.value) {
            changed = true;
        }
        if Identifier::Spork15DeterministicMasternodesEnabled.eq(identifier) {
            if self.chain.is_devnet_any() && self.chain.estimated_block_height() as u64 >= spork.value && self.chain.params.min_protocol_version < SPORK_15_MIN_PROTOCOL_VERSION {
                //use estimated block height here instead
                self.chain.set_min_protocol_version(SPORK_15_MIN_PROTOCOL_VERSION);
            }
        }
        // todo: ?? unused var
    }

    pub fn set_spork_value(&mut self, spork: Spork, identifier: Identifier) {
        self.check_triggers_for_spork(&spork, &identifier);
        self.spork_dictionary.insert(identifier, spork);
    }

    pub fn wipe_spork_info(&mut self) {
        self.spork_dictionary.clear();
        self.stop_getting_sporks();
    }

}
