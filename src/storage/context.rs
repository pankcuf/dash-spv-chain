use std::collections::HashMap;
use crate::storage::manager::managed_context::ManagedContext;
use crate::storage::manager::managed_context_type::ManagedContextType;

#[derive(Debug, Default)]
pub struct StoreContext {
    store: HashMap<ManagedContextType, ManagedContext>
}

impl StoreContext {
    pub fn new() -> Self {
        Self {
            store: HashMap::from([
                (ManagedContextType::View, ManagedContext::default()),
                (ManagedContextType::Chain, ManagedContext::default()),
                (ManagedContextType::Peer, ManagedContext::default()),
                (ManagedContextType::Masternodes, ManagedContext::default()),
                (ManagedContextType::Platform, ManagedContext::default()),
            ])
        }
    }
    pub fn context_for(&self, r#type: ManagedContextType) -> &ManagedContext {
        self.store.get(&r#type).unwrap()
    }

}
