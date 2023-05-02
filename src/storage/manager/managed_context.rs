use std::fmt::Debug;
use diesel::r2d2::ConnectionManager;
use diesel::{QueryResult, SqliteConnection};
use r2d2::{Pool, PooledConnection};
use crate::storage::manager::connection_manager::get_connection_pool;
use crate::storage::models::entity::Entity;

#[derive(Debug)]
pub struct ManagedContext {
    pub pool: Pool<ConnectionManager<SqliteConnection>>,
    // pub chain: &'static ChainEntity,
    // prepared_for_save: HashMap<>
}

impl Default for ManagedContext {
    fn default() -> Self {
        Self { pool: get_connection_pool() }
    }
}

impl<'a> Default for &'a ManagedContext {
    fn default() -> Self {
        &ManagedContext::default()
    }
}

impl ManagedContext {


    pub fn pool(&self) -> &Pool<ConnectionManager<SqliteConnection>> {
        &self.pool
    }

    pub fn connection(&self) -> PooledConnection<ConnectionManager<SqliteConnection>> {
        if let Some(conn) = self.pool.try_get() {
            return conn;
        }
        panic!("Error getting connection from pool");
    }

    pub fn perform_block(&self, block: impl Fn(&ManagedContext)) {
        todo!("Impl");
        block(self)
    }

    pub fn perform_block_and_wait(&self, block: impl Fn(&ManagedContext)) {
        todo!("Impl");
        block(self)
    }

    pub fn prepare<T, U, E, R>(&self, entity: E, executor: impl Fn(E, &ManagedContext) -> QueryResult<R>) -> QueryResult<R>
        where
            E: Entity {
        executor(entity, self)
    }

    pub fn commit(&self) {

    }
}
