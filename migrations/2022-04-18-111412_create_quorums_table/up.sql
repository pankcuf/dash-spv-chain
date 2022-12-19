-- Your SQL goes here
CREATE TABLE quorums (
    id INTEGER PRIMARY KEY NOT NULL,
    block_id INTEGER NOT NULL,
    chain_id INTEGER NOT NULL,
    verified BOOLEAN NOT NULL,
    version SMALLINT NOT NULL,
    all_commitment_aggregated_signature BLOB NOT NULL,
    commitment_hash BLOB NOT NULL,
    commitment_transaction_id INTEGER,
    quorum_index INTEGER,
    quorum_type SMALLINT NOT NULL,
    quorum_hash BLOB NOT NULL,
    quorum_public_key BLOB NOT NULL,
    quorum_threshold_signature BLOB NOT NULL,
    quorum_verification_vector_hash BLOB NOT NULL,
    signers_count INTEGER NOT NULL,
    signers_bitset BLOB NOT NULL,
    valid_members_count INTEGER NOT NULL,
    valid_members_bitset BLOB NOT NULL
)
