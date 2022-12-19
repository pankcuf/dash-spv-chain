-- Your SQL goes here
CREATE TABLE shapeshifts
(
    id INTEGER PRIMARY KEY NOT NULL,
    transaction_id INTEGER NOT NULL,

    input_address VARCHAR NOT NULL,
    input_coin_amount DOUBLE NOT NULL,
    input_coin_type VARCHAR NOT NULL,

    output_coin_amount DOUBLE NOT NULL,
    output_coin_type VARCHAR NOT NULL,
    output_transaction_id VARCHAR NOT NULL,

    expires_at TIMESTAMP NOT NULL,

    shapeshift_status SMALLINT NOT NULL,

    is_fixed_amount BOOLEAN NOT NULL,

    error_message VARCHAR NOT NULL,
    withdrawal_address VARCHAR NOT NULL
)
