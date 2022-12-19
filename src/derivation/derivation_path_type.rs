pub enum DerivationPathType {
    Unknown = 0,
    ClearFunds = 1,
    AnonymousFunds = 1 << 1,
    ViewOnlyFunds = 1 << 2,
    SingleUserAuthentication = 1 << 3,
    MultipleUserAuthentication = 1 << 4,
    PartialPath = 1 << 5,
    ProtectedFunds = 1 << 6,
    CreditFunding = 1 << 7,
    IsForAuthentication = DerivationPathType::SingleUserAuthentication | DerivationPathType::MultipleUserAuthentication,
    IsForFunds = DerivationPathType::ClearFunds | DerivationPathType::AnonymousFunds | DerivationPathType::ViewOnlyFunds | DerivationPathType::ProtectedFunds
}
