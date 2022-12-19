use std::collections::{HashMap, HashSet};
use crate::chain::chain::Chain;
use crate::chain::dispatch_context::DispatchContext;
use crate::dapi::networking::core;
use crate::dapi::networking::platform;
use crate::dapi::networking::platform::protocol::Error;
use crate::platform::base::serializable_object::{SerializableKey, SerializableValue};
use crate::platform::contract::contract::Contract;
use crate::platform::document::Document;
use crate::platform::identity::identity::Identity;
use crate::platform::transition::document_transition::DocumentTransition;
use crate::platform::transition::transition::ITransition;
use crate::storage::manager::managed_context::ManagedContext;

pub struct Client {
    pub chain: &'static Chain,
    pub core_service: core::Service,
    pub platform_service: platform::Service,

    // core_queue: dispatch_queue_t,
    // platform_queue: dispatch_queue_t,
    available_peers: HashSet<String>,
    used_peers: HashSet<String>,
    active_core_services: Vec<core::Service>,
    active_platform_services: Vec<platform::Service>,

}

impl Client {

    pub fn init_with_chain(chain: &Chain) -> Self {
        Self {
            chain,
            core_service: core::Service {},
            platform_service: platform::Service {},
            available_peers: HashSet::new(),
            used_peers: HashSet::new(),
            active_core_services: vec![],
            active_platform_services: vec![],
        }
    }

    pub async fn send_document(&self, document: Document, identity: &Identity, contract: &Contract) -> Result<bool, Error> {
        let document_transition = DocumentTransition::init_for_documents(vec![document], 1, identity.unique_id, self.chain);
        identity.sign
        todo!()
    }

    pub async fn publish_transition(&self, state_transition: &dyn ITransition, context: &ManagedContext, dispatch_context: &DispatchContext) -> Result<(HashMap<dyn SerializableKey, dyn SerializableValue>, bool), Error>{
        todo!()
    }

    pub fn remove_dapi_node_by_address(&mut self, host: &String) {
        self.available_peers.remove(host);
        if let Some(index) = self.active_platform_services.iter().position(|service| service.ip_address == host) {
            self.active_platform_services.remove(index);
        }
    }


}

