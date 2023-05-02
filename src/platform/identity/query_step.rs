
// pub enum QueryStep {
//     None = RegistrationStep::None.into(),         //0
//     Identity = RegistrationStep::Identity.into(), //16
//     Username = RegistrationStep::Username.into(), //32
//     Profile = RegistrationStep::Profile.into(),   //64
//     IncomingContactRequests = 128,
//     OutgoingContactRequests = 256,
//     ContactRequests = QueryStep::IncomingContactRequests | QueryStep::OutgoingContactRequests,
//     AllForForeignBlockchainIdentity = QueryStep::Identity | QueryStep::Username | QueryStep::Profile,
//     AllForLocalBlockchainIdentity = QueryStep::Identity | QueryStep::Username | QueryStep::Profile | QueryStep::ContactRequests,
//     NoIdentity = 1 << 28,
//     BadQuery = 1 << 29,
//     Cancelled = 1 << 30
// }

// pub mod QueryStep {
//     pub const None: u8 = 0;
//     pub const Identity: u8 = 16;
//     pub const Username: u8 = 32;
//     pub const Profile: u8 = 64;
//     pub const IncomingContactRequests: u8 = 128;
//     pub const OutgoingContactRequests: u8 = 256;
//     pub const ContactRequests: u8 = IncomingContactRequests | OutgoingContactRequests;
//     pub const AllForForeignBlockchainIdentity: u8 = Identity | Username | Profile;
//     pub const AllForLocalBlockchainIdentity: u8 = Identity | Username | Profile | ContactRequests;
//     pub const NoIdentity: u8 = 1 << 28;
//     pub const BadQuery: u8 = 1 << 29;
//     pub const Cancelled: u8 = 1 << 30;
//
// }

bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct QueryStep: u16 {
        const None = 0;
        const Identity = 16;
        const Username = 32;
        const Profile = 64;
        const IncomingContactRequests = 128;
        const OutgoingContactRequests = 256;
        const ContactRequests = QueryStep::IncomingContactRequests.bits() | QueryStep::OutgoingContactRequests.bits();
        const AllForForeignBlockchainIdentity = QueryStep::Identity.bits() | QueryStep::Username.bits() | QueryStep::Profile.bits();
        const AllForLocalBlockchainIdentity = QueryStep::AllForForeignBlockchainIdentity.bits() | QueryStep::ContactRequests.bits();
        const NoIdentity = 1 << 28;
        const BadQuery = 1 << 29;
        const Cancelled = 1 << 30;

    }
}
