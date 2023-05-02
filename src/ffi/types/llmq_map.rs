use crate::ffi::types::LLMQEntry;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LLMQMap {
    pub llmq_type: u8,
    pub values: *mut *mut LLMQEntry,
    pub count: usize,
}
