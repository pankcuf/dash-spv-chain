-- Your SQL goes here
CREATE TABLE instant_send_locks
(
    id INTEGER PRIMARY KEY NOT NULL,
    verified BOOLEAN NOT NULL,
    signature BLOB NOT NULL,
    quorum_id INTEGER,
    transaction_id INTEGER NOT NULL
)
