pub enum RegistrationStatus {
    Unknown = 0,
    Registered = 1,
    Registering = 2,
    NotRegistered = 3, //sent to DAPI, not yet confirmed
}
