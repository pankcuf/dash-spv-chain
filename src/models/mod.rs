use byte::{BytesExt, LE};
use crate::crypto::byte_util::BytesDecodable;
use crate::impl_bytes_decodable;

pub use crate::chain::masternode::llmq_entry::LLMQEntry;
pub use crate::chain::masternode::llmq_typed_hash::LLMQIndexedHash;
pub use crate::chain::masternode::llmq_typed_hash::LLMQTypedHash;
pub use crate::chain::masternode::masternode_entry::MasternodeEntry;
pub use crate::chain::masternode::masternode_list::MasternodeList;
pub use crate::chain::masternode::mn_list_diff::MNListDiff;
pub use crate::chain::masternode::operator_public_key::OperatorPublicKey;
pub use crate::chain::masternode::rotation_info::LLMQRotationInfo;
pub use crate::chain::masternode::snapshot::LLMQSnapshot;

impl_bytes_decodable!(MasternodeEntry);
impl_bytes_decodable!(LLMQEntry);
