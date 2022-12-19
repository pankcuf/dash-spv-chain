-- Your SQL goes here
CREATE TABLE identities (
    id INTEGER PRIMARY KEY NOT NULL,
    credit_balance UNSIGNED BIG INT NOT NULL,
    dashpay_sync_block_hash BLOB NOT NULL,
    is_local BOOLEAN NOT NULL,
    registration_status SMALLINT NOT NULL,
    unique_id BLOB NOT NULL,
    last_checked_incoming_contacts_timestamp TIMESTAMP NOT NULL,
    last_checked_outgoing_contacts_timestamp TIMESTAMP NOT NULL,
    last_checked_profile_timestamp TIMESTAMP NOT NULL,
    last_checked_usernames_timestamp TIMESTAMP NOT NULL,

    chain_id INTEGER NOT NULL,
    associated_invitation_id INTEGER,
    dashpay_username_id INTEGER,
    matching_user_id INTEGER,
    registration_funding_id INTEGER
)
