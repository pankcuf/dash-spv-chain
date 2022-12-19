-- Your SQL goes here
CREATE TABLE transaction_outputs
(
    id INTEGER PRIMARY KEY NOT NULL,
    account_id INTEGER,
    local_address_id INTEGER,
    spent_in_input_id INTEGER,
    transaction_id INTEGER NOT NULL,
    address VARCHAR NOT NULL,
    shapeshift_outbound_address VARCHAR,
    n INTEGER NOT NULL,
    value UNSIGNED BIG INT NOT NULL,
    script BLOB NOT NULL,
    tx_hash BLOB NOT NULL
)
