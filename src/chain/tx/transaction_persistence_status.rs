pub enum TransactionPersistenceStatus {
    NotSaved,
    Saving,
    Saved
}

impl Default for TransactionPersistenceStatus {
    fn default() -> Self {
        TransactionPersistenceStatus::NotSaved
    }
}
