-- Your SQL goes here
CREATE TABLE identity_key_paths (
    id INTEGER PRIMARY KEY NOT NULL,
    key_id INTEGER NOT NULL,
    key_status SMALLINT NOT NULL,
    key_type SMALLINT NOT NULL,
    public_key BLOB NOT NULL,
    path BLOB NOT NULL,

    identity_id INTEGER NOT NULL,
    derivation_path_id INTEGER
)
