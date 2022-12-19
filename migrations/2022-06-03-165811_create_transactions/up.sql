-- Your SQL goes here
CREATE TABLE transactions
(
    id INTEGER PRIMARY KEY NOT NULL,
    hash BLOB NOT NULL,
    block_height UNSIGNED INTEGER NOT NULL,
    version UNSIGNED SMALLINT,
    lock_time INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    tx_type UNSIGNED SMALLINT NOT NULL,
-- Special Transaction Stuff
    special_transaction_version UNSIGNED SMALLINT,
    ip_address BLOB,
    port UNSIGNED SMALLINT,
    provider_mode UNSIGNED INTEGER,
    provider_type UNSIGNED INTEGER,
    reason UNSIGNED INTEGER,
    collateral_outpoint BLOB,
    operator_reward BLOB,
    operator_key BLOB,
    owner_key_hash BLOB,
    voting_key_hash BLOB,
    payload_signature BLOB,
    script_payout BLOB,
    quorum_commitment_height UNSIGNED INTEGER,
    mn_list_merkle_root BLOB,
    llmq_list_merkle_root BLOB,
    provider_registration_transaction_hash BLOB,
-- Relationships
    chain_id INTEGER NOT NULL,
    associated_shapeshift_id INTEGER,
    instant_send_lock_id INTEGER,
-- Special Transaction Relationships
    local_masternode_id INTEGER,
    registered_identity_id INTEGER,
    topped_up_identity_id INTEGER,
    quorum_id INTEGER
)
