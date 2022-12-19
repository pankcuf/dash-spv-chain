-- Your SQL goes here
CREATE TABLE peers
(
    id INTEGER PRIMARY KEY NOT NULL,
    chain_id INTEGER NOT NULL,
    address INTEGER NOT NULL,
    port SMALLINT NOT NULL,
    misbehaving SMALLINT NOT NULL,
    priority INTEGER NOT NULL,
    services UNSIGNED BIG INT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    last_requested_governance_sync TIMESTAMP,
    last_requested_masternode_list TIMESTAMP,
    low_preference_till TIMESTAMP NOT NULL
)
