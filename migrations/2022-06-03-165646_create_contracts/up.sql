-- Your SQL goes here
CREATE TABLE contracts
(
    id INTEGER PRIMARY KEY NOT NULL,
    chain_id INTEGER NOT NULL,
    creator_id INTEGER NOT NULL,
    state SMALLINT NOT NULL,
    local_contract_id VARCHAR NOT NULL,
    registered_identity_unique_id BLOB,
    entropy BLOB
)
