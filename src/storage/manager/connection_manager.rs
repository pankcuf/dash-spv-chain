use diesel::connection::SimpleConnection;
use diesel::SqliteConnection;
use diesel::r2d2::{ConnectionManager, Error};
use r2d2::{Pool, PooledConnection};

#[derive(Debug)]
pub struct ConnectionOptions {
    pub enable_wal: bool,
    pub enable_foreign_keys: bool,
    pub busy_timeout: Option<std::time::Duration>,
}

impl r2d2::CustomizeConnection<SqliteConnection, diesel::r2d2::Error> for ConnectionOptions {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), diesel::r2d2::Error> {
        (|| {
            if self.enable_wal {
                conn.batch_execute("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
            }
            if self.enable_foreign_keys {
                conn.batch_execute("PRAGMA foreign_keys = ON;")?;
            }
            if let Some(d) = self.busy_timeout {
                conn.batch_execute(&format!("PRAGMA busy_timeout = {};", d.as_millis()))?;
            }
            Ok(())
        })().map_err(Error::QueryError)
    }
}

/**
 * SQLite doesn't support multiple writers.
 * It's highly preferable to use WAL mode. It improves concurrency by letting readers and writer
 * to work simultaneously (WAL is much faster than journal).
 * This way you can have multiple readers/writers which makes life easier. Multiple writers use locking mechanism (through busy_timeout), so there is one active writer at the time. You certainly don't want to qualify connections as read and write and do locking manually in your application, e.g. with Mutex.
 * See also:
 * https://www.sqlite.org/pragma.html#pragma_synchronous
 * https://www.sqlite.org/rescode.html#busy_snapshot
 * https://www.sqlite.org/wal.html#sometimes_queries_return_sqlite_busy_in_wal_mode
 */
pub fn get_connection_pool() -> Pool<ConnectionManager<SqliteConnection>> {
    Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(ConnectionOptions { enable_wal: true, enable_foreign_keys: true, busy_timeout: Some(std::time::Duration::from_secs(30)) }))
        .build(ConnectionManager::<SqliteConnection>::new("DashSyncRS.sqlite"))
        .unwrap()
}

