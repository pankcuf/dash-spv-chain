-- Your SQL goes here
CREATE TABLE identity_usernames (
    id INTEGER PRIMARY KEY NOT NULL,
    domain VARCHAR NOT NULL,
    salt BLOB NOT NULL,
    status SMALLINT NOT NULL,
    string_value VARCHAR NOT NULL,
    identity_id INTEGER NOT NULL
)
