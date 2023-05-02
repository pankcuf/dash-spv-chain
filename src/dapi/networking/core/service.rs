use crate::chain::dispatch_context::DispatchContext;
use crate::chain::tx::transaction::ITransaction;
use crate::crypto::UInt256;
use crate::util;

#[derive(Debug, Default)]
pub struct Service {

}

impl Service {
    pub async fn get_transaction_with_hash(&self, hash: &UInt256, dispatch_context: &DispatchContext) -> Result<&dyn ITransaction, util::Error> {
        todo!()
    }
}
