use bls_signatures::Scheme;
use byte::BytesExt;
use crate::chain::common::chain_type::IHaveChainSettings;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::{UInt256, UInt768};
use crate::crypto::byte_util::{AsBytes, Zeroable};
use crate::chain::masternode::{LLMQEntry, MasternodeList};
use crate::chain::chain::Chain;
use crate::storage::models::chain::chain_lock::ChainLockEntity;

#[derive(Clone, Copy, Debug, Default)]
pub struct ChainLock {
    pub height: u32,
    pub block_hash: UInt256,
    pub request_id: Option<UInt256>,
    pub signature: UInt768,
    pub signature_verified: bool,
    pub quorum_verified: bool,
    pub saved: bool,
    pub intended_quorum: Option<&'static LLMQEntry>,
    pub chain: &'static Chain,
    // pub input_outpoints: Vec<>
}

impl ChainLock {
    /// message can be either a merkleblock or header message
    pub fn init_with_message(bytes: &[u8], chain: &Chain) -> Option<Self> {
        if bytes.len() < 132 {
            return None;
        }
        let offset = &mut 0;
        let height = bytes.read_with::<u32>(offset, byte::LE).unwrap();
        let block_hash = bytes.read_with::<UInt256>(offset, byte::LE).unwrap();
        let signature = bytes.read_with::<UInt768>(offset, byte::LE).unwrap();
        println!("the chain lock signature received for height {} (sig {}) (blockhash {})", height, signature, block_hash);
        Some(ChainLock {
            height,
            block_hash,
            request_id: None,
            signature,
            signature_verified: false,
            quorum_verified: false,
            saved: false,
            intended_quorum: None,
            chain
        })
    }

    pub fn new(block_hash: UInt256, signature: UInt768, signature_verified: bool, quorum_verified: bool, chain: &Chain) -> Self {
        ChainLock {
            height: 0,
            block_hash,
            request_id: None,
            signature,
            signature_verified,
            quorum_verified,
            saved: true, // this is coming already from the persistant store and not from the network
            intended_quorum: None,
            chain
        }
    }

    pub fn get_request_id(&mut self) -> UInt256 {
        self.request_id.unwrap_or({
            let mut buffer: Vec<u8> = Vec::new();
            "clsig".to_string().enc(&mut buffer);
            self.height.enc(&mut buffer);
            let req_id = UInt256::sha256d(&buffer);
            self.request_id = Some(req_id);
            req_id
        })
        // if let Some(req_id) = self.request_id {
        //     return req_id;
        // } else {
        //     let mut buffer: Vec<u8> = Vec::new();
        //     "clsig".to_string().enc(&mut buffer);
        //     self.height.enc(&mut buffer);
        //     let req_id = UInt256::sha256d(&buffer);
        //     self.request_id = Some(req_id);
        //     req_id
        // }
    }

    pub fn sign_id_for_quorum_entry(&mut self, entry: &LLMQEntry) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::new();
        let lock_type: u8 = self.chain.r#type().chain_locks_type().into();
        let chain_locks_type = VarInt(lock_type as u64);
        chain_locks_type.enc(&mut buffer);
        entry.llmq_hash.enc(&mut buffer);
        self.get_request_id().enc(&mut buffer);
        self.block_hash.enc(&mut buffer);
        UInt256::sha256d(&buffer)
    }

    pub fn verify_signature_against_quorum(&mut self, entry: &LLMQEntry) -> bool {
        let public_key = entry.public_key;
        let use_legacy = entry.version.use_bls_legacy();
        let sign_id = self.sign_id_for_quorum_entry(entry);
        println!("verifying signature <REDACTED> with public key <REDACTED> for transaction hash <REDACTED> against quorum {:?}", entry);
        assert!(public_key.is_zero(), "verify_signature_against_quorum: public_key is empty");
        if use_legacy {
            let bls_public_key = bls_signatures::G1Element::from_bytes_legacy(public_key.as_bytes()).unwrap();
            let bls_signature = bls_signatures::G2Element::from_bytes_legacy(self.signature.as_bytes()).unwrap();
            bls_signatures::LegacySchemeMPL::new().verify(&bls_public_key, sign_id.as_bytes(), &bls_signature)
        } else {
            let bls_public_key = bls_signatures::G1Element::from_bytes(public_key.as_bytes()).unwrap();
            let bls_signature = bls_signatures::G2Element::from_bytes(self.signature.as_bytes()).unwrap();
            bls_signatures::BasicSchemeMPL::new().verify(&bls_public_key, sign_id.as_bytes(), &bls_signature)
        }
    }

    pub fn find_signing_quorum_return_masternode_list(&mut self) -> (Option<&LLMQEntry>, Option<&MasternodeList>) {
        let llmq_type = self.chain.r#type().chain_locks_type();
        let recent_masternode_lists = self.chain.masternode_manager().recent_masternode_lists();
        let mut quorum: Option<&LLMQEntry> = None;
        let mut list: Option<&MasternodeList> = None;
        for masternode_list in recent_masternode_lists {
            if let Some(quorums) = masternode_list.quorums.get(&llmq_type) {
                for (_, entry) in quorums {
                    let signature_verified = self.verify_signature_against_quorum(entry);
                    if signature_verified {
                        quorum = Some(&entry);
                        list = Some(&masternode_list);
                        break;
                    }
                }
            }
            if quorum.is_some() {
                break;
            }
        }
        (quorum, list)
    }

    pub fn verify_signature_with_quorum_offset(&mut self, offset: u32) -> bool {
        if let Some(quorum) = self.chain.masternode_manager().quorum_entry_for_chain_lock_request_id(self.request_id, self.height - offset) {
            if quorum.verified {
                self.signature_verified = self.verify_signature_against_quorum(quorum);
            }
            if self.signature_verified {
                self.intended_quorum = Some(quorum);
                // We should also set the chain's last chain lock
                self.chain.update_last_chain_lock_if_need(self);
            } else if quorum.verified && offset == 8 {
                return self.verify_signature_with_quorum_offset(0);
            } else if quorum.verified && offset == 0 {
                return self.verify_signature_with_quorum_offset(16);
            }
            println!("returning chain lock signature verified {} with offset {}", self.signature_verified, offset);
        }
        self.signature_verified
    }

    pub fn verify_signature(&mut self) -> bool {
        self.verify_signature_with_quorum_offset(8)
    }

    pub fn save_initial(&mut self) {
        if self.saved {
            return;
        }
        // TODO: saving here will only create, not update
        self.chain.chain_context().perform_block_and_wait(|context| {
            if let Err(err) = ChainLockEntity::create_if_need(self, context) {
                println!("ChainLock saving error: {}", err);
            } else {
                self.saved = true;
            }
        });
    }

    pub fn save_signature_valid(&mut self) {
        if !self.saved {
            self.save_initial();
            return;
        }
        self.chain.chain_context().perform_block_and_wait(|context| {
            ChainLockEntity::update_signature_valid_if_need(self, context)
                .expect("Can't update signature for chain lock entity");
        });
    }
}

