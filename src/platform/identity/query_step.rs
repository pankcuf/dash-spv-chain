use crate::platform::identity::registration_step::RegistrationStep;

pub enum QueryStep {
    None = RegistrationStep::None.into(),         //0
    Identity = RegistrationStep::Identity.into(), //16
    Username = RegistrationStep::Username.into(), //32
    Profile = RegistrationStep::Profile.into(),   //64
    IncomingContactRequests = 128,
    OutgoingContactRequests = 256,
    ContactRequests = QueryStep::IncomingContactRequests | QueryStep::OutgoingContactRequests,
    AllForForeignBlockchainIdentity = QueryStep::Identity | QueryStep::Username | QueryStep::Profile,
    AllForLocalBlockchainIdentity = QueryStep::Identity | QueryStep::Username | QueryStep::Profile | QueryStep::ContactRequests,
    NoIdentity = 1 << 28,
    BadQuery = 1 << 29,
    Cancelled = 1 << 30
}
