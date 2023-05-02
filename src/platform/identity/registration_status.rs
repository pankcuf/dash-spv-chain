#[derive(Clone, Debug, Default, PartialEq)]
pub enum RegistrationStatus {
    #[default]
    Unknown = 0,
    Registered = 1,
    Registering = 2,
    NotRegistered = 3, //sent to DAPI, not yet confirmed
}
