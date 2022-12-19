
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use crate::crypto::{BDictionary, Boolean, UInt128, UInt160, UInt256, UInt384, UInt768};
    use crate::hashes::hex::FromHex;
    use crate::models::masternode::masternode::{create_masternode, masternode_with_entry_hash, masternode_with_pro_reg_tx_hash};
    use crate::models::masternode::masternode_list::{create_masternode_list, delete_masternode_list, masternode_list_for_block, update_masternode_list};
    use crate::models::masternode::quorum::{create_quorum, quorum_for_commitment_hash};

    #[test]
    fn test_masternode_list_crud() {
        let _block_hash = UInt256::from_hex("0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let block_id = 0;
        let chain_id = 0;
        let masternodes_merkle_root = UInt256::from_hex("0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let quorums_merkle_root = UInt256::from_hex("0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let result = create_masternode_list(block_id, chain_id, masternodes_merkle_root, quorums_merkle_root);
        println!("Saved {:?} entries", result);
        let result = masternode_list_for_block(chain_id, block_id);
        println!("Read: {:?}", result);
        let list = result.unwrap();
        assert_eq!(list.block_id, block_id);
        assert_eq!(list.masternodes_merkle_root, masternodes_merkle_root);
        assert_eq!(list.quorums_merkle_root, quorums_merkle_root);
        let masternodes_merkle_root = UInt256::from_hex("ff00000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let quorums_merkle_root = UInt256::from_hex("ff00000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let result = update_masternode_list(block_id, chain_id, masternodes_merkle_root, quorums_merkle_root);
        println!("Updated {:?} entries", result);
        let result = masternode_list_for_block(chain_id, block_id);
        println!("Read: {:?}", list);
        let list = result.unwrap();
        assert_eq!(list.block_id, block_id);
        assert_eq!(list.masternodes_merkle_root, masternodes_merkle_root);
        assert_eq!(list.quorums_merkle_root, quorums_merkle_root);
        let count = delete_masternode_list(chain_id, block_id);
        println!("Deleted {:?} entries", count);
        let result = masternode_list_for_block(chain_id, block_id);
        println!("Read (): {:?}", result); // diesel::result::Error::NotFound
        assert!(result.is_err());
    }

    #[test]
    fn test_masternode_crud() {
        let chain_id = 0;
        let address = 0xffffff33ff33ff;
        let port =  20000;
        let core_last_connection_date = chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd(2022, 5, 30),
            chrono::NaiveTime::from_hms_milli(12, 34, 56, 789)
        );
        let core_protocol = 20222;
        let core_version = "core_version";
        let is_valid = true;
        let platform_ping = 10;
        let platform_ping_date = chrono::NaiveDateTime::new(
            chrono::NaiveDate::from_ymd(2022, 5, 30),
            chrono::NaiveTime::from_hms_milli(12, 34, 56, 789)
        );
        let platform_version = "platform_version";
        let known_confirmed_at_height = 0;
        let update_height = 0;
        let local_masternode_id = 0;

        let mut bmap_keys = BTreeMap::new();
        bmap_keys.insert(
            UInt256::from_hex("5500000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
            UInt384::from_hex("ff1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap()
        );
        bmap_keys.insert(
            UInt256::from_hex("6600000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
            UInt384::from_hex("001c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap()
        );

        let mut bmap_hashes = BTreeMap::new();
        bmap_hashes.insert(
            UInt256::from_hex("5500000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
            UInt256::from_hex("7700000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap()
        );
        bmap_hashes.insert(
            UInt256::from_hex("6600000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
            UInt256::from_hex("8800000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap()
        );
        let mut bmap_val = BTreeMap::new();
        bmap_val.insert(
            UInt256::from_hex("9800000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
            Boolean(true)
        );
        bmap_val.insert(
            UInt256::from_hex("9900000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap(),
            Boolean(false)
        );

        let prev_operator_bls_public_keys = BDictionary::new(bmap_keys);
        let prev_masternode_entry_hashes = BDictionary::new(bmap_hashes);
        let prev_validity = BDictionary::new(bmap_val);
        let confirmed_hash = UInt256::from_hex("0000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let ipv6_address = UInt128::from_hex("ee1c7de7fe063c7d81405293a9764733").unwrap();
        let key_id_voting = UInt160::from_hex("ee1c7de7fe063c7d81405293a976473310e7c080").unwrap();
        let operator_bls_public_key = UInt384::from_hex("ee1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let provider_registration_transaction_hash = UInt256::from_hex("1100000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();
        let masternode_entry_hash = UInt256::from_hex("2200000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();


        let result = create_masternode(
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
            operator_bls_public_key,
            provider_registration_transaction_hash,
            masternode_entry_hash
        );

        println!("Saved {:?} entry", result);
        let result = masternode_with_pro_reg_tx_hash(chain_id, provider_registration_transaction_hash);
        println!("Read: {:?}", result);
        let masternode = result.unwrap();
        assert_eq!(masternode.key_id_voting, key_id_voting);
        assert_eq!(masternode.masternode_entry_hash, masternode_entry_hash);

        let operator_bls_public_key = UInt384::from_hex("ee1c7de7fe063c7d81405293a97647330000000000000010e7c080046121900cee1c7de7fe063c7d81405293a9764733").unwrap();

        let result = masternode_with_entry_hash(chain_id, masternode_entry_hash);
        println!("Read: {:?}", result);
        let masternode = result.unwrap();
        assert_eq!(masternode.ipv6_address, ipv6_address);
        assert_eq!(masternode.platform_ping_date, Some(platform_ping_date));

    }

    #[test]
    pub fn test_quorum_crud() {

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

        let result = create_quorum(
            block_id, chain_id, verified, version, all_commitment_aggregated_signature,
            commitment_hash, commitment_transaction_id, quorum_index, quorum_type, quorum_hash,
            quorum_public_key, quorum_threshold_signature, quorum_verification_vector_hash,
            signers_count, signers_bitset, valid_members_count, valid_members_bitset.clone()
        );

        println!("Saved {:?} entry", result);
        let result = quorum_for_commitment_hash(chain_id, commitment_hash);
        println!("Read: {:?}", result);
        let quorum = result.unwrap();
        assert_eq!(quorum.quorum_hash, quorum_hash);
        assert_eq!(quorum.valid_members_bitset, valid_members_bitset.clone());

    }
}
