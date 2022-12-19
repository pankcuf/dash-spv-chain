-- Your SQL goes here
CREATE TABLE derivation_paths
(
    id INTEGER PRIMARY KEY NOT NULL,
    chain_id INTEGER NOT NULL,
    account_id INTEGER,
    friend_request_id INTEGER,
    sync_block_height INTEGER NOT NULL,
    public_key_identifier VARCHAR NOT NULL,
    derivation_path BLOB
)
