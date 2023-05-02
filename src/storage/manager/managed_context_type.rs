#[derive(Debug, Default, Eq, Hash, PartialEq)]
pub enum ManagedContextType {
    View,
    Peer,
    #[default]
    Chain,
    Masternodes,
    Platform
}
