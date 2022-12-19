-- Your SQL goes here
CREATE TABLE governance_votes
(
    id INTEGER PRIMARY KEY NOT NULL,
    chain_id INTEGER NOT NULL,
    masternode INTEGER NOT NULL,
    masternode_index INTEGER NOT NULL,
    masternode_hash BLOB NOT NULL,

    outcome INTEGER NOT NULL,
    signal INTEGER NOT NULL,

    timestamp_created TIMESTAMP NOT NULL,

    parent_hash BLOB NOT NULL,
    signature BLOB NOT NULL,

    object_id INTEGER NOT NULL,
    vote_hash BLOB NOT NULL,
    vote_timestamp TIMESTAMP NOT NULL
)
