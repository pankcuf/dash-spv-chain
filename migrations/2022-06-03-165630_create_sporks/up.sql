-- Your SQL goes here
CREATE TABLE sporks
(
    id INTEGER PRIMARY KEY NOT NULL,
    chain_id INTEGER NOT NULL,
    identifier INTEGER NOT NULL,
    time_signed BIG INT NOT NULL,
    value BIG INT NOT NULL,
    spork_hash BLOB NOT NULL,
    signature BLOB NOT NULL
)
