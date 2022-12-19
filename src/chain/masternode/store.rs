use std::collections::BTreeMap;
use crate::crypto::UInt256;
use crate::models::MasternodeList;

pub struct Store {
    pub masternode_lists_by_block_hash: BTreeMap<UInt256, MasternodeList>,
}
