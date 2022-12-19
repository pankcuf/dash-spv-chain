-- Your SQL goes here
CREATE TABLE masternode_list_quorums (
    masternode_list_id INTEGER NOT NULL,
    quorum_id INTEGER NOT NULL,
    PRIMARY KEY (masternode_list_id, quorum_id)
)
