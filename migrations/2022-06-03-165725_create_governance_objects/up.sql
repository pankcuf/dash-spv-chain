-- Your SQL goes here
CREATE TABLE governance_objects
(
    id INTEGER PRIMARY KEY NOT NULL,
    chain_id INTEGER NOT NULL,
    amount UNSIGNED BIG INT NOT NULL,
    start_epoch UNSIGNED BIG INT NOT NULL,
    end_epoch UNSIGNED BIG INT NOT NULL,
    revision INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    total_votes_count UNSIGNED BIG INT NOT NULL,
    object_type INTEGER NOT NULL,
    identifier VARCHAR NOT NULL,
    payment_address VARCHAR NOT NULL,
    url VARCHAR NOT NULL,

    collateral_hash BLOB NOT NULL,
    parent_hash BLOB NOT NULL,
    signature BLOB NOT NULL,

    hash BLOB NOT NULL,
    hash_timestamp TIMESTAMP NOT NULL
)
