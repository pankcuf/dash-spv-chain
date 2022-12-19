-- Your SQL goes here
CREATE TABLE checkpoints
(
    id INTEGER PRIMARY KEY NOT NULL,
    height INTEGER NOT NULL,
    hash BLOB NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    target INTEGER NOT NULL,
    masternode_list_path VARCHAR,
    merkle_root BLOB,
    chain_work BLOB NOT NULL,

    chain_id INTEGER NOT NULL
)
