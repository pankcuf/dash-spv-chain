CREATE TABLE provider_registration_transactions
(
    id INTEGER PRIMARY KEY NOT NULL,
    base_id INTEGER NOT NULL,

    local_masternode_id INTEGER NOT NULL,

    provider_mode SMALLINT NOT NULL,
    provider_type SMALLINT NOT NULL,

    ip_address BLOB NOT NULL,
    port SMALLINT NOT NULL,
    operator_reward SMALLINT NOT NULL,

    collateral_outpoint BLOB NOT NULL,
    operator_key BLOB NOT NULL,
    owner_key_hash BLOB NOT NULL,
    voting_key_hash BLOB NOT NULL,
    payload_signature BLOB NOT NULL,
    script_payout BLOB NOT NULL
)
