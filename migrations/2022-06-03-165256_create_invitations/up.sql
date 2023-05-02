-- Your SQL goes here
CREATE TABLE invitations (
    id INTEGER PRIMARY KEY NOT NULL,
    link VARCHAR,
    name VARCHAR,
    tag VARCHAR,
    identity_id INTEGER NOT NULL,
    chain_id INTEGER NOT NULL
)
