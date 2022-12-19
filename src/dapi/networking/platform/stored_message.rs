#[derive(Debug)]
pub enum StoredMessage {
    /// The item does not exist for the specified key
    NotPresent = 0,
    /// The version is prepended before all items
    Version,
    /// An item can be returned if decode is set to true
    Item,
    /// A data item that can be returned if decode is set to false
    Data,
}
