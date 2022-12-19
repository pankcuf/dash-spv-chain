use std::collections::HashMap;
use diesel::r2d2::ConnectionManager;
use diesel::{QueryResult, SqliteConnection};
use r2d2::{Pool, PooledConnection};
use crate::storage::models::chain::chain::ChainEntity;
use crate::storage::models::entity::Entity;

pub struct ManagedContext {
    pub pool: Pool<ConnectionManager<SqliteConnection>>,
    // pub chain: &'static ChainEntity,
    // prepared_for_save: HashMap<>
}

impl ManagedContext {


    pub fn pool(&self) -> &Pool<ConnectionManager<SqliteConnection>> {
        &pool
    }

    pub fn connection(&self) -> PooledConnection<ConnectionManager<SqliteConnection>> {
        if let Some(conn) = self.pool.try_get() {
            return conn;
        }
        panic!("Error getting connection from pool");
    }

    pub fn perform_block(&self, block: fn(&ManagedContext)) {
        todo!("Impl");
        block(self)
    }

    pub fn perform_block_and_wait(&self, block: fn(&ManagedContext)) {
        todo!("Impl");
        block(self)
    }

    pub fn prepare<T, U, E, R>(&self, entity: E, executor: fn(E, &ManagedContext) -> QueryResult<R>) -> QueryResult<R>
        where
            E: Entity {
        executor(entity, self)
    }

    pub fn commit(&self) {

    }
}
