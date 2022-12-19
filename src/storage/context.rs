use std::collections::HashMap;
use crate::{ManagedContextType, ManagedContext, get_connection_pool};

pub struct StoreContext {
    store: HashMap<ManagedContextType, ManagedContext>
}

impl StoreContext {
    pub fn new() -> Self {
        Self {
            store: HashMap::from([
                (ManagedContextType::View, ManagedContext { pool: get_connection_pool() }),
                (ManagedContextType::Chain, ManagedContext { pool: get_connection_pool() }),
                (ManagedContextType::Peer, ManagedContext { pool: get_connection_pool() }),
                (ManagedContextType::Masternodes, ManagedContext { pool: get_connection_pool() }),
                (ManagedContextType::Platform, ManagedContext { pool: get_connection_pool() }),
            ])
        }
    }
    pub fn context_for(&self, r#type: ManagedContextType) -> &ManagedContext {
        self.store.get(&r#type).unwrap()
    }

}
