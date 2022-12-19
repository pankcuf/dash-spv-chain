-- Your SQL goes here
CREATE TABLE masternode_list_masternodes (
    masternode_list_id INTEGER NOT NULL,
    masternode_id INTEGER NOT NULL,
    PRIMARY KEY (masternode_list_id, masternode_id)
)
