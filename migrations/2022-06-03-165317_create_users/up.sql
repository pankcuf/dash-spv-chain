-- Your SQL goes here
CREATE TABLE users (
    id INTEGER PRIMARY KEY NOT NULL,
    local_profile_document_revision INTEGER NOT NULL,
    remote_profile_document_revision INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    avatar_path VARCHAR,
    display_name VARCHAR,
    public_message VARCHAR,
    avatar_fingerprint UNSIGNED BIG INT,
    avatar_hash BLOB,
    document_id BLOB,
    original_entropy_data BLOB,
    identity_id INTEGER NOT NULL,
    chain_id INTEGER NOT NULL
)
