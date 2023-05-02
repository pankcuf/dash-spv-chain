use std::collections::HashMap;
use std::{env, fs};
use bip39::Language;
use crate::chain::common::chain_type::DevnetType;
use crate::chain::common::ChainType;
use crate::chain::chain::Chain;
use crate::chain::checkpoint::{Checkpoint, MAINNET_CHECKPOINT_ARRAY, TESTNET_CHECKPOINT_ARRAY};
use crate::chain::params::{create_devnet_params_for_type, MAINNET_PARAMS, TESTNET_PARAMS};
use crate::keychain::keychain::{Keychain, KeychainDictValueKind};
use crate::chain::chain_sync_phase::ChainSyncPhase;
use crate::chain::dispatch_context::DispatchContext;
use crate::chain::ext::sync_progress::SyncProgress;
use crate::chain::sync_count_info::SyncCountInfo;
use crate::environment::Environment;
use crate::storage::context::StoreContext;
use crate::chain::wallet::wallet::Wallet;
use crate::manager::authentication_manager::AuthenticationManager;
use crate::manager::peer_manager::{LAST_SYNCED_GOVERANCE_OBJECTS, LAST_SYNCED_MASTERNODE_LIST};
use crate::network::network_context::NetworkContext;
use crate::notifications::{Notification, NotificationCenter};
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::chain::spork::SporkEntity;
use crate::storage::models::common::peer::PeerEntity;
use crate::storage::models::entity::Entity;
use crate::storage::models::masternode::{LocalMasternodeEntity, MasternodeEntity, MasternodeListEntity, QuorumEntity};
use crate::storage::models::masternode::llmq_snapshot::LLMQSnapshotEntity;
use crate::user_defaults::UserDefaults;

pub const DEVNET_CHAINS_KEY: &str = "DEVNET_CHAINS_KEY";

#[derive(Debug, Default)]
pub struct ChainsManager<'a> {
    pub(crate) chains: Vec<&'a Chain>,
    pub(crate) mainnet: Chain,
    pub(crate) testnet: Chain,
    pub(crate) devnet_chains: Vec<&'a Chain>,
    pub environment: Environment,
    pub authentication_manager: AuthenticationManager,
}

impl<'a> ChainsManager<'a> {
    pub fn new(language: Language) -> Self {
        let classes = vec!["String".to_string(), "Array".to_string(), "Checkpoint".to_string()];
        let mut devnet_chains = Vec::<&Chain>::new();
        // let mut registered_devnet_identifiers = vec![];
        // if let Some(dictionaryFromKeyChain) = Keychain::get_dict::<String, Vec<Checkpoint>>(DEVNET_CHAINS_KEY.to_string(), classes) {
        //     registered_devnet_identifiers.extend(dictionaryFromKeyChain);
        // }
        //self.reachability = [DSReachabilityManager sharedManager];
        // TODO: impl state initial_loading
        let environment = Environment::new(language);
        let authentication_manager = AuthenticationManager::new(&environment);
        let mainnet = Chain::new(
            MAINNET_PARAMS,
            MAINNET_CHECKPOINT_ARRAY,
            &authentication_manager,
            &environment,
            NetworkContext::new(),
            StoreContext::new());
        let testnet = Chain::new(
            TESTNET_PARAMS,
            TESTNET_CHECKPOINT_ARRAY,
            &authentication_manager,
            &environment,
            NetworkContext::new(),
            StoreContext::new());
        let mut chains = vec![&mainnet, &testnet];
        // chains.extend(devnet_chains);
        Self {
            mainnet,
            testnet,
            chains,
            devnet_chains,
            environment,
            authentication_manager,
        }
    }

    pub fn has_a_wallet(&self) -> bool {
        self.chains.iter().find(|&chain| chain.has_a_wallet()).is_some() ||
            self.devnet_chains.iter().find(|&chain| chain.has_a_wallet()).is_some()
    }

    pub fn all_wallets(&self) -> Vec<&Wallet> {
        let mut all_wallets = Vec::<&Wallet>::new();
        self.chains.iter().for_each(|chain| all_wallets.extend(chain.wallets.clone()));
        for chain in self.chains {
            all_wallets.extend(chain.wallets.clone());
        }
        for chain in self.devnet_chains {
            all_wallets.extend(chain.wallets.clone());
        }
        all_wallets
    }

    pub fn create_devnet(&mut self, r#type: DevnetType) -> Chain {
        let params = create_devnet_params_for_type(r#type);
        let genesis_checkpoint = Checkpoint::genesis_devnet_checkpoint();
        let second_checkpoint = Checkpoint::create_dev_net_genesis_block_checkpoint_for_parent_checkpoint(
            genesis_checkpoint, r#type, params.base_reward, &params.script_map, params.protocol_version.clone());
        Chain::new(
            params,
            vec![genesis_checkpoint, second_checkpoint],
            &self.authentication_manager,
            &self.environment,
            NetworkContext::new(),
            StoreContext::new())
    }

    pub fn remove_devnet(&mut self, chain: &mut Chain) {
        if let ChainType::DevNet(devnet_type) = chain.r#type() {
            let masternode_manager = chain.masternode_manager();
            // masternode_manager.destroy_processors();
            chain.peer_manager().clear_registered_peers();
            let mut registered_devnets_dictionary = Keychain::get_dict::<String, KeychainDictValueKind>(DEVNET_CHAINS_KEY.to_string()).unwrap_or(HashMap::new());
            if registered_devnets_dictionary.contains_key(&devnet_type.identifier()) {
                registered_devnets_dictionary.remove(&devnet_type.identifier());
                Keychain::set_dict::<String, KeychainDictValueKind>(registered_devnets_dictionary, DEVNET_CHAINS_KEY.to_string(), false).expect("");
            }
            chain.wipe_wallets_and_derivatives();

            let context = chain.chain_context();
            self.wipe_peer_data_for_chain(chain, context);
            self.wipe_blockchain_data_for_chain(chain, context);
            self.wipe_spork_data_for_chain(chain, context);
            self.wipe_masternode_data_for_chain(chain, context);
            self.wipe_governance_data_for_chain(chain, context);
            self.wipe_wallet_data_for_chain(chain, false, context);
            if let Some(pos) = self.devnet_chains.iter().position(|&x| x == chain) {
                self.devnet_chains.remove(pos);
            }
            DispatchContext::main_context().queue(||
                NotificationCenter::post(Notification::ChainsDidChange));
        }
    }

    pub fn start_sync_for_chain(&self, chain: &Chain) {
        chain.start_sync();
    }

    pub fn stop_sync_all_chains(&self) {
        self.chains.iter().for_each(|chain| chain.peer_manager().disconnect());
        self.devnet_chains.iter().for_each(|chain| chain.peer_manager().disconnect());
    }

    pub fn stop_sync_for_chain(&self, chain: &mut Chain) {
        chain.stop_sync();
    }


    pub fn wipe_peer_data_for_chain(&self, mut chain: &Chain, context: &ManagedContext) {
        self.stop_sync_for_chain(&mut chain);
        let mut peer_manager = chain.peer_manager();
        peer_manager.remove_trusted_peer_host();
        peer_manager.clear_peers();
        match PeerEntity::delete_all_peers_for_chain(chain.r#type(), context) {
            Ok(deleted) => println!("All peer entities for chain {:?} are deleted", chain.r#type()),
            Err(err) => println!("Error deleting peer entities: {}", err)
        }
    }

    pub fn wipe_blockchain_data_for_chain(&self, mut chain: &mut Chain, context: &ManagedContext) {
        self.stop_sync_for_chain(&mut chain);
        match ChainEntity::wipe_blockchain_data(chain.r#type(), context) {
            Ok(deleted) => {
                chain.wipe_blockchain_info(context);
                chain.restart_chain_sync_start_height();
                chain.restart_chain_terminal_sync_start_height();
                chain.sync_phase = ChainSyncPhase::InitialTerminalBlocks;
                chain.reload_derivation_paths();
                chain.assign_sync_weights();
                DispatchContext::main_context().queue(|| {
                    NotificationCenter::post(Notification::WalletBalanceDidChange);
                    NotificationCenter::post(Notification::ChainSyncBlocksDidChange(chain));
                    NotificationCenter::post(Notification::ChainTerminalBlocksDidChange(chain));
                })
            },
            Err(err) => println!("Error deleting chain entity {:?}", chain.r#type())
        }
    }

    pub fn wipe_blockchain_non_terminal_data_for_chain(&self, mut chain: &mut Chain, context: &ManagedContext) {
        self.stop_sync_for_chain(&mut chain);
        match ChainEntity::wipe_blockchain_non_terminal_data(chain.r#type(), context) {
            Ok(deleted) => {
                chain.wipe_blockchain_non_terminal_info(context);
                chain.restart_chain_sync_start_height();
                chain.reload_derivation_paths();
                chain.assign_sync_weights();
                DispatchContext::main_context().queue(|| {
                    NotificationCenter::post(Notification::WalletBalanceDidChange);
                    NotificationCenter::post(Notification::ChainSyncBlocksDidChange(chain));
                    NotificationCenter::post(Notification::ChainTerminalBlocksDidChange(chain));
                })
            },
            Err(err) => println!("Error deleting chain entity {:?}", chain.r#type())
        }
    }

    pub fn wipe_masternode_data_for_chain(&self, mut chain: &mut Chain, context: &ManagedContext) {
        self.stop_sync_for_chain(&mut chain);
        match ChainEntity::get_chain(chain.r#type(), context) {
            Ok(entity) => {
                let chain_id = entity.id;
                LocalMasternodeEntity::delete_by_chain_id(chain_id, context).expect("Can't delete local masternode entities for chain");
                MasternodeEntity::delete_by_chain_id(chain_id, context).expect("Can't delete masternode entities for chain");
                QuorumEntity::delete_by_chain_id(chain_id, context).expect("Can't delete llmq entities for chain");
                MasternodeListEntity::delete_by_chain_id(chain_id, context).expect("Can't delete masternode list entities for chain");
                LLMQSnapshotEntity::delete_by_chain_id(chain_id, context).expect("Can't delete llmq snapshot entities for chain");
                // chain.wipe_masternodes_in_context(context);
                chain.assign_sync_weights();
                UserDefaults::remove_object_for_key(format!("{}_{}", chain.unique_id, LAST_SYNCED_MASTERNODE_LIST).as_str());
                DispatchContext::main_context().queue(|| {
                    NotificationCenter::post(Notification::MasternodeListDidChange(chain));
                })
            },
            Err(err) => println!("Error retrieving chain entity {:?}", chain.r#type())
        }
    }

    pub fn wipe_spork_data_for_chain(&self, mut chain: &mut Chain, context: &ManagedContext) {
        self.stop_sync_for_chain(&mut chain);
        match ChainEntity::get_chain(chain.r#type(), context) {
            Ok(entity) => {
                SporkEntity::delete_by_chain_id(entity.id, context).expect("Can't delete spork entities for chain");
                chain.spork_manager().wipe_spork_info();
                UserDefaults::remove_object_for_key(format!("{}_{}", chain.unique_id, LAST_SYNCED_MASTERNODE_LIST).as_str());
                DispatchContext::main_context().queue(|| {
                    NotificationCenter::post(Notification::SporkListDidUpdate { chain, old: None, new: None });
                })
            },
            Err(err) => println!("Error retrieving chain entity {:?}", chain.r#type())
        }
    }

    pub fn wipe_governance_data_for_chain(&self, mut chain: &mut Chain, context: &ManagedContext) {
        self.stop_sync_for_chain(&mut chain);
        chain.reset_sync_count_info(SyncCountInfo::GovernanceObject, context);
        chain.reset_sync_count_info(SyncCountInfo::GovernanceObjectVote, context);
        chain.governance_sync_manager().wipe_governance_info();
        UserDefaults::remove_object_for_key(format!("{}_{}", chain.unique_id, LAST_SYNCED_GOVERANCE_OBJECTS).as_str());
        DispatchContext::main_context().queue(|| {
            NotificationCenter::post(Notification::GovernanceObjectListDidChange(chain));
            NotificationCenter::post(Notification::GovernanceVotesDidChange(chain));
            NotificationCenter::post(Notification::GovernanceObjectCountUpdate(chain));
            NotificationCenter::post(Notification::GovernanceVoteCountUpdate(chain));
        });
    }

    pub async fn wipe_wallet_data_for_chain(&self, mut chain: &mut Chain, force_reauth: bool, context: &ManagedContext) {
        self.stop_sync_for_chain(&mut chain);
        match ChainEntity::wipe_wallet_data(chain.r#type(), context) {
            Ok(deleted) => {
                chain.wipe_blockchain_info(context);
                chain.restart_chain_sync_start_height();

                chain.restart_chain_terminal_sync_start_height();
                chain.sync_phase = ChainSyncPhase::InitialTerminalBlocks;
                chain.reload_derivation_paths();
                chain.wipe_masternode_info();
                chain.assign_sync_weights();
                UserDefaults::remove_object_for_key(format!("{}_{}", chain.unique_id, LAST_SYNCED_MASTERNODE_LIST).as_str());
                DispatchContext::main_context().queue(|| {
                    NotificationCenter::post(Notification::WalletBalanceDidChange);
                    NotificationCenter::post(Notification::ChainSyncBlocksDidChange(chain));
                    NotificationCenter::post(Notification::ChainTerminalBlocksDidChange(chain));
                    NotificationCenter::post(Notification::MasternodeListDidChange(chain));
                });
            },
            Err(err) => println!("Error deleting chain entity {:?}", chain.r#type())
        }
        if !force_reauth && self.authentication_manager.did_authenticate {
            chain.wipe_wallets_and_derivatives();
            DispatchContext::main_context().queue(|| {
                NotificationCenter::post(Notification::ChainStandaloneDerivationPathsDidChange(chain));
                NotificationCenter::post(Notification::WalletsDidChange(chain));
                NotificationCenter::post(Notification::ChainStandaloneDerivationPathsDidChange(chain));
            });
        } else {
            match self.authentication_manager.authenticate_with_prompt(
                Some(format!("Wipe wallets")), false, false).await {
                Ok((authenticatedOrSuccess, usedBiometrics, cancelled)) => {
                    chain.wipe_wallets_and_derivatives();
                    DispatchContext::main_context().queue(|| {
                        NotificationCenter::post(Notification::ChainStandaloneDerivationPathsDidChange(chain));
                        NotificationCenter::post(Notification::WalletsDidChange(chain));
                        NotificationCenter::post(Notification::ChainStandaloneDerivationPathsDidChange(chain));
                    });
                },
                Err(err) => println!("Error authenticating {:?}", chain.r#type())
            }
        }
    }

    pub fn db_size(&self) -> u64 {
        let store_url = env::var("DATABASE_URL").unwrap();
        if let Ok(meta) = fs::metadata(store_url) {
            meta.len() as u64
        } else {
            0
        }
    }

}
