-- Your SQL goes here
CREATE TABLE masternode_lists (
    id INTEGER PRIMARY KEY NOT NULL,
    block_id INTEGER NOT NULL,
    chain_id INTEGER NOT NULL,
    masternodes_merkle_root BLOB,
    quorums_merkle_root BLOB
)
