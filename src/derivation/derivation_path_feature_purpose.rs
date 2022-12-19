pub enum DerivationPathFeaturePurpose {
    DEFAULT = 9,
    IDENTITIES = 5,
    IDENTITIES_SUBFEATURE_AUTHENTICATION = 0,
    IDENTITIES_SUBFEATURE_REGISTRATION = 1,
    IDENTITIES_SUBFEATURE_TOPUP = 2,
    IDENTITIES_SUBFEATURE_INVITATIONS = 3,
    DASHPAY = 15,
}

impl From<u32> for DerivationPathFeaturePurpose {
    fn from(orig: u32) -> Self {
        match orig {
            0 => DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_AUTHENTICATION,
            1 => DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_REGISTRATION,
            2 => DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_TOPUP,
            3 => DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_INVITATIONS,
            5 => DerivationPathFeaturePurpose::IDENTITIES,
            9 => DerivationPathFeaturePurpose::DEFAULT,
            15 => DerivationPathFeaturePurpose::DASHPAY,
            _ => DerivationPathFeaturePurpose::DEFAULT,
        }
    }
}

impl From<DerivationPathFeaturePurpose> for u32 {
    fn from(value: DerivationPathFeaturePurpose) -> Self {
        match value {
            DerivationPathFeaturePurpose::DEFAULT => 9,
            DerivationPathFeaturePurpose::IDENTITIES => 5,
            DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_AUTHENTICATION => 0,
            DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_REGISTRATION => 1,
            DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_TOPUP => 2,
            DerivationPathFeaturePurpose::IDENTITIES_SUBFEATURE_INVITATIONS => 3,
            DerivationPathFeaturePurpose::DASHPAY => 15,
        }
    }
}
