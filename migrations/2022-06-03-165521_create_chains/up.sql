-- Your SQL goes here
CREATE TABLE chains (
    id INTEGER PRIMARY KEY NOT NULL,
    chain_type SMALLINT NOT NULL,
    version SMALLINT,
    identifier VARCHAR,
    total_governance_objects_count INTEGER NOT NULL,
    last_chain_lock_id INTEGER,
    base_block_hash BLOB,

    sync_block_chain_work BLOB,
    sync_block_hash BLOB,
    sync_block_height INTEGER,
    sync_block_timestamp TIMESTAMP,
    sync_locators BLOB
)
