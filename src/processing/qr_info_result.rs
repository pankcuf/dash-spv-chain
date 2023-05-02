use crate::chain::masternode;
use crate::processing::{MNListDiffResult, ProcessingError};

#[derive(Debug)]
pub struct QRInfoResult {
    pub error_status: ProcessingError,
    pub result_at_tip: MNListDiffResult,
    pub result_at_h: MNListDiffResult,
    pub result_at_h_c: MNListDiffResult,
    pub result_at_h_2c: MNListDiffResult,
    pub result_at_h_3c: MNListDiffResult,
    pub result_at_h_4c: Option<MNListDiffResult>,

    pub snapshot_at_h_c: masternode::LLMQSnapshot,
    pub snapshot_at_h_2c: masternode::LLMQSnapshot,
    pub snapshot_at_h_3c: masternode::LLMQSnapshot,
    pub snapshot_at_h_4c: Option<masternode::LLMQSnapshot>,

    pub extra_share: bool,
    pub last_quorum_per_index: Vec<masternode::LLMQEntry>,
    pub quorum_snapshot_list: Vec<masternode::LLMQSnapshot>,
    pub mn_list_diff_list: Vec<MNListDiffResult>,
}
impl Default for QRInfoResult {
    fn default() -> Self {
        Self {
            error_status: ProcessingError::None,
            result_at_tip: Default::default(),
            result_at_h: Default::default(),
            result_at_h_c: Default::default(),
            result_at_h_2c: Default::default(),
            result_at_h_3c: Default::default(),
            result_at_h_4c: None,
            snapshot_at_h_c: Default::default(),
            snapshot_at_h_2c: Default::default(),
            snapshot_at_h_3c: Default::default(),
            snapshot_at_h_4c: None,
            extra_share: false,
            last_quorum_per_index: vec![],
            quorum_snapshot_list: vec![],
            mn_list_diff_list: vec![],
        }
    }
}

impl QRInfoResult {
    pub fn default_with_error(error: ProcessingError) -> Self {
        Self { error_status: error, ..Self::default() }
    }
}
