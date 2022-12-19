CREATE TABLE quorum_commitment_transactions
(
    id INTEGER PRIMARY KEY NOT NULL,
    base_id INTEGER NOT NULL,

    quorum_id INTEGER NOT NULL,
    quorum_commitment_height INTEGER NOT NULL
)
