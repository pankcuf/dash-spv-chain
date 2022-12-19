-- Your SQL goes here
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY NOT NULL,
    "index" INTEGER NOT NULL,
    chain_id INTEGER NOT NULL,
    wallet_unique_id VARCHAR NOT NULL
)
