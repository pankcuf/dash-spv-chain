-- Your SQL goes here
CREATE TABLE friend_requests (
    id INTEGER PRIMARY KEY NOT NULL,
    account_id INTEGER NOT NULL,
    source_key_index INTEGER NOT NULL,
    destination_key_index INTEGER NOT NULL,
    source_contact_id INTEGER NOT NULL,
    destination_contact_id INTEGER NOT NULL,
    derivation_path_id INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    friendship_identifier BLOB
)
