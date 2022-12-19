CREATE TABLE provider_update_registrar_transactions
(
    id INTEGER PRIMARY KEY NOT NULL,
    base_id INTEGER NOT NULL,

    local_masternode_id INTEGER NOT NULL,

    provider_mode SMALLINT NOT NULL,

    operator_key BLOB NOT NULL,
    provider_registration_transaction_hash BLOB NOT NULL,
    voting_key_hash BLOB NOT NULL,

    payload_signature BLOB NOT NULL,
    script_payout BLOB NOT NULL
)
