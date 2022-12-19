-- Your SQL goes here
CREATE TABLE masternode_addresses (
    address_id INTEGER NOT NULL,
    masternode_id INTEGER NOT NULL,
--     addresses INTEGER,
--     used_in_masternodes_ids INTEGER,
--     fok_2_addresses INTEGER,
    PRIMARY KEY (address_id, masternode_id)
)
