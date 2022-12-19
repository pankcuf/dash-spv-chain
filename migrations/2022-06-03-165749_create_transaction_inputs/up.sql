-- Your SQL goes here
CREATE TABLE transaction_inputs
(
    id INTEGER PRIMARY KEY NOT NULL,
    n INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    signature BLOB NOT NULL,
    tx_hash BLOB NOT NULL,
    local_address_id INTEGER,
    prev_output_id INTEGER,
    transaction_id INTEGER NOT NULL
)
