-- Your SQL goes here
CREATE TABLE invitations (
    id INTEGER PRIMARY KEY NOT NULL,
    identity_id INTEGER NOT NULL,
    chain_id INTEGER NOT NULL,
    link VARCHAR NOT NULL
)
