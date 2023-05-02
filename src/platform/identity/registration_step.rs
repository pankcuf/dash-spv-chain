// pub enum RegistrationStep {
//     None = 0,
//     FundingTransactionCreation = 1,
//     FundingTransactionAccepted = 2,
//     LocalInWalletPersistence = 4,
//     ProofAvailable = 8,
//     L1Steps = RegistrationStep::FundingTransactionCreation | RegistrationStep::FundingTransactionAccepted | RegistrationStep::LocalInWalletPersistence | RegistrationStep::ProofAvailable,
//     Identity = 16,
//     RegistrationSteps = RegistrationStep::L1Steps | RegistrationStep::Identity,
//     Username = 32,
//     RegistrationStepsWithUsername = RegistrationStep::RegistrationSteps | RegistrationStep::Username,
//     Profile = 64,
//     RegistrationStepsWithUsernameAndDashpayProfile = RegistrationStep::RegistrationStepsWithUsername | RegistrationStep::Profile,
//     All = RegistrationStep::RegistrationStepsWithUsername | RegistrationStep::Profile,
//     Cancelled = 1 << 30
// }

// pub mod RegistrationStep {
//     pub const None: u8 = 0;
//     pub const FundingTransactionCreation: u8 = 1;
//     pub const FundingTransactionAccepted: u8 = 2;
//     pub const LocalInWalletPersistence: u8 = 4;
//     pub const ProofAvailable: u8 = 8;
//     pub const L1Steps: u8 = FundingTransactionCreation | FundingTransactionAccepted | LocalInWalletPersistence | ProofAvailable;
//     pub const Identity: u8 = 16;
//     pub const RegistrationSteps: u8 = L1Steps | Identity;
//     pub const Username: u8 = 32;
//     pub const RegistrationStepsWithUsername: u8 = RegistrationSteps | Username;
//     pub const Profile: u8 = 64;
//     pub const RegistrationStepsWithUsernameAndDashpayProfile: u8 = RegistrationStepsWithUsername | Profile;
//     pub const All: u8 = RegistrationStepsWithUsernameAndDashpayProfile;
//     pub const Cancelled: u8 = 1 << 30;
// }
bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct RegistrationStep: u8 {
        const None = 0;
        const FundingTransactionCreation = 1;
        const FundingTransactionAccepted = 2;
        const LocalInWalletPersistence = 4;
        const ProofAvailable = 8;
        const L1Steps = RegistrationStep::FundingTransactionCreation.bits() | RegistrationStep::FundingTransactionAccepted.bits() | RegistrationStep::LocalInWalletPersistence.bits() | RegistrationStep::ProofAvailable.bits();
        const Identity = 16;
        const RegistrationSteps = RegistrationStep::L1Steps.bits() | RegistrationStep::Identity.bits();
        const Username = 32;
        const RegistrationStepsWithUsername = RegistrationStep::RegistrationSteps.bits() | RegistrationStep::Username.bits();
        const Profile = 64;
        const RegistrationStepsWithUsernameAndDashpayProfile = RegistrationStep::RegistrationStepsWithUsername.bits() | RegistrationStep::Profile.bits();
        const All = RegistrationStep::RegistrationStepsWithUsernameAndDashpayProfile.bits();
        const Cancelled = 1 << 30;
    }
}
