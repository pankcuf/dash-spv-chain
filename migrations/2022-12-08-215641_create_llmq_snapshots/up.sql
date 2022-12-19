-- Your SQL goes here
CREATE TABLE llmq_snapshots
(
    id INTEGER PRIMARY KEY NOT NULL,

    member_list BLOB NOT NULL,
    skip_list BLOB NOT NULL,
    skip_list_mode INTEGER NOT NULL,

    block_id INTEGER NOT NULL
)
