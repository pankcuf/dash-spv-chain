-- Your SQL goes here
CREATE TABLE blocks
(
    id INTEGER PRIMARY KEY NOT NULL,
    chain_id INTEGER NOT NULL,
    chain_lock_id INTEGER,
    masternode_list_id INTEGER,
    height INTEGER NOT NULL,
    block_hash BLOB NOT NULL,
    chain_work BLOB NOT NULL,
    merkle_root BLOB NOT NULL,
    prev_block BLOB NOT NULL,

    nonce INTEGER NOT NULL,
    target INTEGER NOT NULL,
    total_transactions INTEGER NOT NULL,
    version INTEGER NOT NULL,

    timestamp TIMESTAMP NOT NULL,

    flags BLOB,
    hashes BLOB
)
