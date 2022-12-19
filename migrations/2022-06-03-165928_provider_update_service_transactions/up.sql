CREATE TABLE provider_update_service_transactions
(
    id INTEGER PRIMARY KEY NOT NULL,
    base_id INTEGER NOT NULL,

    local_masternode_id INTEGER NOT NULL,

    ip_address BLOB NOT NULL,
    port SMALLINT NOT NULL,

    provider_registration_transaction_hash BLOB NOT NULL,
    payload_signature BLOB NOT NULL,
    script_payout BLOB NOT NULL
)
