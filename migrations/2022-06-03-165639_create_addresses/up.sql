-- Your SQL goes here
CREATE TABLE addresses
(
    id INTEGER PRIMARY KEY NOT NULL,
    identity_index INTEGER NOT NULL,
    "index" INTEGER NOT NULL,
    address VARCHAR NOT NULL,
    internal BOOLEAN NOT NULL,
    standalone BOOLEAN NOT NULL,

    derivation_path_id INTEGER
)
