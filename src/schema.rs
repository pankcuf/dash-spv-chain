table! {
    accounts (id) {
        id -> Integer,
        index -> Integer,
        chain_id -> Integer,
        wallet_unique_id -> Text,
    }
}

table! {
    addresses (id) {
        id -> Integer,
        identity_index -> Integer,
        index -> Integer,
        address -> Text,
        internal -> Bool,
        standalone -> Bool,
        derivation_path_id -> Nullable<Integer>,
    }
}

table! {
    blocks (id) {
        id -> Integer,
        chain_id -> Integer,
        chain_lock_id -> Nullable<Integer>,
        masternode_list_id -> Nullable<Integer>,
        height -> Integer,
        block_hash -> Binary,
        chain_work -> Binary,
        merkle_root -> Binary,
        prev_block -> Binary,
        nonce -> Integer,
        target -> Integer,
        total_transactions -> Integer,
        version -> Integer,
        timestamp -> Timestamp,
        flags -> Nullable<Binary>,
        hashes -> Nullable<Binary>,
    }
}

table! {
    chain_locks (id) {
        id -> Integer,
        verified -> Bool,
        signature -> Binary,
        block_id -> Integer,
        quorum_id -> Nullable<Integer>,
        chain_id -> Nullable<Integer>,
    }
}

table! {
    chains (id) {
        id -> Integer,
        chain_type -> SmallInt,
        version -> Nullable<SmallInt>,
        identifier -> Nullable<Text>,
        total_governance_objects_count -> Integer,
        last_chain_lock_id -> Nullable<Integer>,
        base_block_hash -> Nullable<Binary>,
        sync_block_chain_work -> Nullable<Binary>,
        sync_block_hash -> Nullable<Binary>,
        sync_block_height -> Nullable<Integer>,
        sync_block_timestamp -> Nullable<Timestamp>,
        sync_locators -> Nullable<Binary>,
    }
}

table! {
    checkpoints (id) {
        id -> Integer,
        height -> Integer,
        hash -> Binary,
        timestamp -> Timestamp,
        target -> Integer,
        masternode_list_path -> Nullable<Text>,
        merkle_root -> Nullable<Binary>,
        chain_work -> Binary,
        chain_id -> Integer,
    }
}

table! {
    coinbase_transactions (id) {
        id -> Integer,
        base_id -> Integer,
        height -> Integer,
        merkle_root_mn_list -> Binary,
        locked_amount -> BigInt,
    }
}

table! {
    contracts (id) {
        id -> Integer,
        chain_id -> Integer,
        creator_id -> Integer,
        state -> SmallInt,
        local_contract_id -> Text,
        registered_identity_unique_id -> Nullable<Binary>,
        entropy -> Nullable<Binary>,
    }
}

table! {
    credit_funding_transactions (id) {
        id -> Integer,
        base_id -> Integer,
        registered_identity_id -> Integer,
        topped_up_identity_id -> Integer,
    }
}

table! {
    derivation_paths (id) {
        id -> Integer,
        chain_id -> Integer,
        account_id -> Nullable<Integer>,
        friend_request_id -> Nullable<Integer>,
        sync_block_height -> Integer,
        public_key_identifier -> Text,
        derivation_path -> Nullable<Binary>,
    }
}

table! {
    friend_requests (id) {
        id -> Integer,
        account_id -> Integer,
        source_key_index -> Integer,
        destination_key_index -> Integer,
        source_contact_id -> Integer,
        destination_contact_id -> Integer,
        derivation_path_id -> Integer,
        timestamp -> Timestamp,
        friendship_identifier -> Nullable<Binary>,
    }
}

table! {
    governance_objects (id) {
        id -> Integer,
        chain_id -> Integer,
        amount -> BigInt,
        start_epoch -> BigInt,
        end_epoch -> BigInt,
        revision -> Integer,
        timestamp -> Timestamp,
        total_votes_count -> BigInt,
        object_type -> Integer,
        identifier -> Text,
        payment_address -> Text,
        url -> Text,
        collateral_hash -> Binary,
        parent_hash -> Binary,
        signature -> Binary,
        hash -> Binary,
        hash_timestamp -> Timestamp,
    }
}

table! {
    governance_votes (id) {
        id -> Integer,
        chain_id -> Integer,
        masternode -> Integer,
        masternode_index -> Integer,
        masternode_hash -> Binary,
        outcome -> Integer,
        signal -> Integer,
        timestamp_created -> Timestamp,
        parent_hash -> Binary,
        signature -> Binary,
        object_id -> Integer,
        vote_hash -> Binary,
        vote_timestamp -> Timestamp,
    }
}

table! {
    identities (id) {
        id -> Integer,
        credit_balance -> BigInt,
        dashpay_sync_block_hash -> Binary,
        is_local -> Bool,
        registration_status -> SmallInt,
        unique_id -> Binary,
        last_checked_incoming_contacts_timestamp -> Timestamp,
        last_checked_outgoing_contacts_timestamp -> Timestamp,
        last_checked_profile_timestamp -> Timestamp,
        last_checked_usernames_timestamp -> Timestamp,
        chain_id -> Integer,
        associated_invitation_id -> Nullable<Integer>,
        dashpay_username_id -> Nullable<Integer>,
        matching_user_id -> Nullable<Integer>,
        registration_funding_id -> Nullable<Integer>,
    }
}

table! {
    identity_key_paths (id) {
        id -> Integer,
        key_id -> Integer,
        key_status -> SmallInt,
        key_type -> SmallInt,
        public_key -> Binary,
        path -> Binary,
        identity_id -> Integer,
        derivation_path_id -> Nullable<Integer>,
    }
}

table! {
    identity_usernames (id) {
        id -> Integer,
        domain -> Text,
        salt -> Binary,
        status -> SmallInt,
        string_value -> Text,
        identity_id -> Integer,
    }
}

table! {
    instant_send_locks (id) {
        id -> Integer,
        verified -> Bool,
        signature -> Binary,
        quorum_id -> Nullable<Integer>,
        transaction_id -> Integer,
    }
}

table! {
    invitations (id) {
        id -> Integer,
        link -> Nullable<Text>,
        name -> Nullable<Text>,
        tag -> Nullable<Text>,
        identity_id -> Integer,
        chain_id -> Integer,
    }
}

table! {
    llmq_snapshots (id) {
        id -> Integer,
        member_list -> Binary,
        skip_list -> Binary,
        skip_list_mode -> Integer,
        block_id -> Integer,
    }
}

table! {
    local_masternodes (id) {
        id -> Integer,
        holding_keys_index -> Nullable<Integer>,
        operator_keys_index -> Nullable<Integer>,
        owner_keys_index -> Nullable<Integer>,
        voting_keys_index -> Nullable<Integer>,
        holding_keys_wallet_unique_id -> Nullable<Text>,
        operator_keys_wallet_unique_id -> Nullable<Text>,
        owner_keys_wallet_unique_id -> Nullable<Text>,
        voting_keys_wallet_unique_id -> Nullable<Text>,
        provider_registration_transaction_id -> Nullable<Integer>,
        masternode_id -> Nullable<Integer>,
    }
}

table! {
    masternode_addresses (address_id, masternode_id) {
        address_id -> Integer,
        masternode_id -> Integer,
    }
}

table! {
    masternode_list_masternodes (masternode_list_id, masternode_id) {
        masternode_list_id -> Integer,
        masternode_id -> Integer,
    }
}

table! {
    masternode_list_quorums (masternode_list_id, quorum_id) {
        masternode_list_id -> Integer,
        quorum_id -> Integer,
    }
}

table! {
    masternode_lists (id) {
        id -> Integer,
        block_id -> Integer,
        chain_id -> Integer,
        masternodes_merkle_root -> Binary,
        quorums_merkle_root -> Nullable<Binary>,
    }
}

table! {
    masternodes (id) {
        id -> Integer,
        chain_id -> Integer,
        address -> BigInt,
        port -> SmallInt,
        core_last_connection_date -> Nullable<Timestamp>,
        core_protocol -> BigInt,
        core_version -> Nullable<Text>,
        is_valid -> Bool,
        platform_ping -> BigInt,
        platform_ping_date -> Nullable<Timestamp>,
        platform_version -> Nullable<Text>,
        known_confirmed_at_height -> Integer,
        update_height -> Integer,
        local_masternode_id -> Nullable<Integer>,
        prev_operator_bls_public_keys -> Nullable<Binary>,
        prev_masternode_entry_hashes -> Nullable<Binary>,
        prev_validity -> Nullable<Binary>,
        confirmed_hash -> Binary,
        ipv6_address -> Binary,
        key_id_voting -> Binary,
        operator_bls_public_key -> Binary,
        provider_registration_transaction_hash -> Binary,
        masternode_entry_hash -> Binary,
    }
}

table! {
    peers (id) {
        id -> Integer,
        chain_id -> Integer,
        address -> Integer,
        port -> SmallInt,
        misbehaving -> SmallInt,
        priority -> Integer,
        services -> BigInt,
        timestamp -> Timestamp,
        last_requested_governance_sync -> Nullable<Timestamp>,
        last_requested_masternode_list -> Nullable<Timestamp>,
        low_preference_till -> Timestamp,
    }
}

table! {
    provider_registration_transactions (id) {
        id -> Integer,
        base_id -> Integer,
        local_masternode_id -> Integer,
        provider_mode -> SmallInt,
        provider_type -> SmallInt,
        ip_address -> Binary,
        port -> SmallInt,
        operator_reward -> SmallInt,
        collateral_outpoint -> Binary,
        operator_key -> Binary,
        owner_key_hash -> Binary,
        voting_key_hash -> Binary,
        payload_signature -> Binary,
        script_payout -> Binary,
    }
}

table! {
    provider_update_registrar_transactions (id) {
        id -> Integer,
        base_id -> Integer,
        local_masternode_id -> Integer,
        provider_mode -> SmallInt,
        operator_key -> Binary,
        provider_registration_transaction_hash -> Binary,
        voting_key_hash -> Binary,
        payload_signature -> Binary,
        script_payout -> Binary,
    }
}

table! {
    provider_update_revocation_transactions (id) {
        id -> Integer,
        base_id -> Integer,
        local_masternode_id -> Integer,
        reason -> SmallInt,
        provider_registration_transaction_hash -> Binary,
        payload_signature -> Binary,
    }
}

table! {
    provider_update_service_transactions (id) {
        id -> Integer,
        base_id -> Integer,
        local_masternode_id -> Integer,
        ip_address -> Binary,
        port -> SmallInt,
        provider_registration_transaction_hash -> Binary,
        payload_signature -> Binary,
        script_payout -> Binary,
    }
}

table! {
    quorum_commitment_transactions (id) {
        id -> Integer,
        base_id -> Integer,
        quorum_id -> Integer,
        quorum_commitment_height -> Integer,
    }
}

table! {
    quorums (id) {
        id -> Integer,
        block_id -> Integer,
        chain_id -> Integer,
        verified -> Bool,
        version -> SmallInt,
        all_commitment_aggregated_signature -> Binary,
        commitment_hash -> Binary,
        commitment_transaction_id -> Nullable<Integer>,
        quorum_index -> Nullable<Integer>,
        quorum_type -> SmallInt,
        quorum_hash -> Binary,
        quorum_public_key -> Binary,
        quorum_threshold_signature -> Binary,
        quorum_verification_vector_hash -> Binary,
        signers_count -> Integer,
        signers_bitset -> Binary,
        valid_members_count -> Integer,
        valid_members_bitset -> Binary,
    }
}

table! {
    shapeshifts (id) {
        id -> Integer,
        transaction_id -> Integer,
        input_address -> Text,
        input_coin_amount -> Double,
        input_coin_type -> Text,
        output_coin_amount -> Double,
        output_coin_type -> Text,
        output_transaction_id -> Text,
        expires_at -> Timestamp,
        shapeshift_status -> SmallInt,
        is_fixed_amount -> Bool,
        error_message -> Text,
        withdrawal_address -> Text,
    }
}

table! {
    sporks (id) {
        id -> Integer,
        chain_id -> Integer,
        identifier -> Integer,
        time_signed -> BigInt,
        value -> BigInt,
        spork_hash -> Binary,
        signature -> Binary,
        marked_for_retrieval -> Nullable<SmallInt>,
    }
}

table! {
    transaction_inputs (id) {
        id -> Integer,
        n -> Integer,
        sequence -> Integer,
        signature -> Binary,
        tx_hash -> Binary,
        local_address_id -> Nullable<Integer>,
        prev_output_id -> Nullable<Integer>,
        transaction_id -> Integer,
    }
}

table! {
    transaction_outputs (id) {
        id -> Integer,
        account_id -> Nullable<Integer>,
        local_address_id -> Nullable<Integer>,
        spent_in_input_id -> Nullable<Integer>,
        transaction_id -> Integer,
        address -> Text,
        shapeshift_outbound_address -> Nullable<Text>,
        n -> Integer,
        value -> BigInt,
        script -> Binary,
        tx_hash -> Binary,
    }
}

table! {
    transactions (id) {
        id -> Integer,
        hash -> Binary,
        block_height -> Integer,
        version -> Nullable<SmallInt>,
        lock_time -> Integer,
        timestamp -> Timestamp,
        tx_type -> SmallInt,
        special_transaction_version -> Nullable<SmallInt>,
        height -> Nullable<Integer>,
        ip_address -> Nullable<Binary>,
        port -> Nullable<SmallInt>,
        provider_mode -> Nullable<SmallInt>,
        provider_type -> Nullable<SmallInt>,
        reason -> Nullable<Integer>,
        collateral_outpoint -> Nullable<Binary>,
        operator_reward -> Nullable<SmallInt>,
        operator_key -> Nullable<Binary>,
        owner_key_hash -> Nullable<Binary>,
        voting_key_hash -> Nullable<Binary>,
        payload_signature -> Nullable<Binary>,
        script_payout -> Nullable<Binary>,
        quorum_commitment_height -> Nullable<Integer>,
        mn_list_merkle_root -> Nullable<Binary>,
        llmq_list_merkle_root -> Nullable<Binary>,
        provider_registration_transaction_hash -> Nullable<Binary>,
        chain_id -> Integer,
        associated_shapeshift_id -> Nullable<Integer>,
        instant_send_lock_id -> Nullable<Integer>,
        local_masternode_id -> Nullable<Integer>,
        registered_identity_id -> Nullable<Integer>,
        topped_up_identity_id -> Nullable<Integer>,
        quorum_id -> Nullable<Integer>,
    }
}

table! {
    users (id) {
        id -> Integer,
        local_profile_document_revision -> Integer,
        remote_profile_document_revision -> Integer,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        avatar_path -> Nullable<Text>,
        display_name -> Nullable<Text>,
        public_message -> Nullable<Text>,
        avatar_fingerprint -> Nullable<BigInt>,
        avatar_hash -> Nullable<Binary>,
        document_id -> Nullable<Binary>,
        original_entropy_data -> Nullable<Binary>,
        identity_id -> Integer,
        chain_id -> Integer,
    }
}

allow_tables_to_appear_in_same_query!(
    accounts,
    addresses,
    blocks,
    chain_locks,
    chains,
    checkpoints,
    coinbase_transactions,
    contracts,
    credit_funding_transactions,
    derivation_paths,
    friend_requests,
    governance_objects,
    governance_votes,
    identities,
    identity_key_paths,
    identity_usernames,
    instant_send_locks,
    invitations,
    llmq_snapshots,
    local_masternodes,
    masternode_addresses,
    masternode_list_masternodes,
    masternode_list_quorums,
    masternode_lists,
    masternodes,
    peers,
    provider_registration_transactions,
    provider_update_registrar_transactions,
    provider_update_revocation_transactions,
    provider_update_service_transactions,
    quorum_commitment_transactions,
    quorums,
    shapeshifts,
    sporks,
    transaction_inputs,
    transaction_outputs,
    transactions,
    users,
);
