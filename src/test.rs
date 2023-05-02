
#[cfg(test)]
mod tests {
    use crate::chain::masternode::OperatorPublicKey;
    use crate::crypto::{Boolean, UInt128, UInt160, UInt256, UInt384, UInt768};
    use crate::hashes::hex::FromHex;
    use crate::storage::manager::managed_context::ManagedContext;
    use crate::storage::models::masternode::masternode::{MasternodeEntryHashAtBlockHash, OperatorPublicKeyAtBlockHash, ValidityAtBlockHash};
    use crate::storage::models::masternode::{MasternodeEntity, MasternodeListEntity, QuorumEntity};

    #[test]
    fn test_masternode_list_crud() {
        let context = ManagedContext::default();
        let _block_hash = UInt256::from_hex("0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let block_id = 0;
        let chain_id = 0;
        let masternodes_merkle_root = UInt256::from_hex("0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let quorums_merkle_root = UInt256::from_hex("0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let result = MasternodeListEntity::create_masternode_list(block_id, chain_id, masternodes_merkle_root, Some(quorums_merkle_root), &context);

        println!("Saved {:?} entries", result);
        let result = MasternodeListEntity::masternode_list_for_block(chain_id, block_id, &context);
        println!("Read: {:?}", result);
        let list = result.unwrap();
        assert_eq!(list.block_id, block_id);
        assert_eq!(list.masternodes_merkle_root, masternodes_merkle_root);
        assert_eq!(list.quorums_merkle_root, Some(quorums_merkle_root));
        let masternodes_merkle_root = UInt256::from_hex("ff00000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let quorums_merkle_root = UInt256::from_hex("ff00000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let result = MasternodeListEntity::update_masternode_list(block_id, chain_id, masternodes_merkle_root, quorums_merkle_root, &context);
        println!("Updated {:?} entries", result);
        let result = MasternodeListEntity::masternode_list_for_block(chain_id, block_id, &context);
        println!("Read: {:?}", list);
        let list = result.unwrap();
        assert_eq!(list.block_id, block_id);
        assert_eq!(list.masternodes_merkle_root, masternodes_merkle_root);
        assert_eq!(list.quorums_merkle_root, Some(quorums_merkle_root));
        let count = MasternodeListEntity::delete_masternode_list(chain_id, block_id, &context);
        println!("Deleted {:?} entries", count);
        let result = MasternodeListEntity::masternode_list_for_block(chain_id, block_id, &context);
        println!("Read (): {:?}", result); // diesel::result::Error::NotFound
        assert!(result.is_err());
    }

    #[test]
    fn test_masternode_crud() {
        let context = ManagedContext::default();
        let chain_id = 0;
        let address = 0xffffff33ff33ff;
        let port =  20000;
        let core_last_connection_date = chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2022, 5, 30).unwrap(),
            chrono::NaiveTime::from_hms_milli_opt(12, 34, 56, 789).unwrap()
        );
        let core_protocol = 20222;
        let core_version = "core_version";
        let is_valid = true;
        let platform_ping = 10;
        let platform_ping_date = chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(2022, 5, 30).unwrap(),
            chrono::NaiveTime::from_hms_milli_opt(12, 34, 56, 789).unwrap()
        );
        let platform_version = "platform_version";
        let known_confirmed_at_height = 0;
        let update_height = 0;
        let local_masternode_id = 0;

        let prev_operator_bls_public_keys = vec![
            OperatorPublicKeyAtBlockHash {
                block_hash: UInt256::from_hex("5500000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
                key: OperatorPublicKey {
                    data: UInt384::from_hex("ff1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
                    version: 1
                }
            },
            OperatorPublicKeyAtBlockHash {
                block_hash: UInt256::from_hex("6600000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
                key: OperatorPublicKey {
                    data: UInt384::from_hex("001c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
                    version: 1
                }
            },
        ];
        let prev_masternode_entry_hashes = vec![
            MasternodeEntryHashAtBlockHash {
                block_hash: UInt256::from_hex("5500000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
                entry_hash: UInt256::from_hex("7700000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap()
            },
            MasternodeEntryHashAtBlockHash {
                block_hash: UInt256::from_hex("6600000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
                entry_hash: UInt256::from_hex("8800000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap()
            }
        ];
        let prev_validity = vec![
            ValidityAtBlockHash {
                block_hash: UInt256::from_hex("9800000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
                validity: Boolean(true)
            },
            ValidityAtBlockHash {
                block_hash: UInt256::from_hex("9900000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
                validity: Boolean(false)
            }
        ];
        let confirmed_hash = UInt256::from_hex("0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let ipv6_address = UInt128::from_hex("ee1c7de7fe063c7d81405293a9764733").unwrap();
        let key_id_voting = UInt160::from_hex("ee1c7de7fe063c7d81405293a976473310e7c080").unwrap();
        let operator_bls_public_key = UInt384::from_hex("ee1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let provider_registration_transaction_hash = UInt256::from_hex("1100000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let masternode_entry_hash = UInt256::from_hex("2200000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();


        let result = MasternodeEntity::create_masternode(
            chain_id,
            address,
            port,
            Some(core_last_connection_date),
            core_protocol,
            Some(core_version),
            is_valid,
            platform_ping,
            Some(platform_ping_date),
            Some(platform_version),
            known_confirmed_at_height,
            update_height,
            Some(local_masternode_id),
            prev_operator_bls_public_keys,
            prev_masternode_entry_hashes,
            prev_validity,
            confirmed_hash,
            ipv6_address,
            key_id_voting,
            OperatorPublicKey { data: operator_bls_public_key, version: 1},
            provider_registration_transaction_hash,
            masternode_entry_hash,
            &context
        );

        println!("Saved {:?} entry", result);
        let result = MasternodeEntity::masternode_with_pro_reg_tx_hash(chain_id, provider_registration_transaction_hash, &context);
        println!("Read: {:?}", result);
        let masternode = result.unwrap();
        assert_eq!(masternode.key_id_voting, key_id_voting);
        assert_eq!(masternode.masternode_entry_hash, masternode_entry_hash);

        let operator_bls_public_key = UInt384::from_hex("ee1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();

        let result = MasternodeEntity::masternode_with_entry_hash(chain_id, masternode_entry_hash, &context);
        println!("Read: {:?}", result);
        let masternode = result.unwrap();
        assert_eq!(masternode.ipv6_address, ipv6_address);
        assert_eq!(masternode.platform_ping_date, Some(platform_ping_date));

    }

    #[test]
    pub fn test_quorum_crud() {
        let context = ManagedContext::default();
        let quorum_type = 4;
        let quorum_index = None;
        let signers_count = 100;
        let valid_members_count = 100;
        let verified = false;
        let version = 1;
        let block_id = 8458;
        let chain_id = 3;
        let commitment_transaction_id = None;
        let all_commitment_aggregated_signature = UInt768::from_hex("ee1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733ee1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let commitment_hash = UInt256::from_hex("2200000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764777").unwrap();
        let quorum_hash = UInt256::from_hex("2200000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764765").unwrap();
        let quorum_public_key = UInt384::from_hex("ee1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let quorum_threshold_signature = UInt768::from_hex("aa1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733ee1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let quorum_verification_vector_hash = UInt256::from_hex("2200000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764711").unwrap();

        let signers_bitset = Vec::new();
        let valid_members_bitset = Vec::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f000000000000000000000000").unwrap();

        let result = QuorumEntity::create_quorum(
            block_id, chain_id, verified, version, all_commitment_aggregated_signature,
            commitment_hash, commitment_transaction_id, quorum_index, quorum_type, quorum_hash,
            quorum_public_key, quorum_threshold_signature, quorum_verification_vector_hash,
            signers_count, signers_bitset, valid_members_count, valid_members_bitset.clone(),
            &context
        );

        println!("Saved {:?} entry", result);
        let result = QuorumEntity::quorum_for_commitment_hash(chain_id, commitment_hash, &context);
        println!("Read: {:?}", result);
        let quorum = result.unwrap();
        assert_eq!(quorum.quorum_hash, quorum_hash);
        assert_eq!(quorum.valid_members_bitset, valid_members_bitset.clone());

    }

    #[test]
    fn test_add_le() {
        // let x11 = "020000002cc0081be5039a54b686d24d5d8747ee9770d9973ec1ace02e5c0500000000008d7139724b11c52995db4370284c998b9114154b120ad3486f1a360a1d4253d310d40e55b8f70a1be8e32300";
        // let x11_vec = Vec::from_hex(x11).unwrap();
        // let md = get_x11_hash(x11_vec);
        // println!("input: {}", x11);
        // println!("output: {:?}", md.encode_hex::<String>());
        // assert_eq!(md, Vec::from_hex("f29c0f286fd8071669286c6987eb941181134ff5f3978bf89f34070000000000").unwrap())
    }

}
