-- Your SQL goes here
CREATE TABLE coinbase_transactions
(
    id INTEGER PRIMARY KEY NOT NULL,
    base_id INTEGER NOT NULL,

    height INTEGER NOT NULL,
    merkle_root_mn_list BLOB NOT NULL
)
