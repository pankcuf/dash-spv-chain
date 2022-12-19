CREATE TABLE provider_update_revocation_transactions
(
    id INTEGER PRIMARY KEY NOT NULL,
    base_id INTEGER NOT NULL,

    local_masternode_id INTEGER NOT NULL,

    reason SMALLINT NOT NULL,

    provider_registration_transaction_hash BLOB NOT NULL,
    payload_signature BLOB NOT NULL
)
