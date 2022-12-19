pub enum RegistrationStep {
    None = 0,
    FundingTransactionCreation = 1,
    FundingTransactionAccepted = 2,
    LocalInWalletPersistence = 4,
    ProofAvailable = 8,
    L1Steps = RegistrationStep::FundingTransactionCreation | RegistrationStep::FundingTransactionAccepted | RegistrationStep::LocalInWalletPersistence | RegistrationStep::ProofAvailable,
    Identity = 16,
    RegistrationSteps = RegistrationStep::L1Steps | RegistrationStep::Identity,
    Username = 32,
    RegistrationStepsWithUsername = RegistrationStep::RegistrationSteps | RegistrationStep::Username,
    Profile = 64,
    RegistrationStepsWithUsernameAndDashpayProfile = RegistrationStep::RegistrationStepsWithUsername | RegistrationStep::Profile,
    All = RegistrationStep::RegistrationStepsWithUsername | RegistrationStep::Profile,
    Cancelled = 1 << 30

}
