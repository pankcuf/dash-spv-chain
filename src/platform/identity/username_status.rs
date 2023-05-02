#[derive(Debug)]
pub enum UsernameStatus {
    NotPresent = 0,
    Initial = 1,
    PreorderRegistrationPending = 2,
    Preordered = 3,
    RegistrationPending = 4, //sent to DAPI, not yet confirmed
    Confirmed = 5,
    TakenOnNetwork = 6,
}

impl From<u32> for UsernameStatus {
    fn from(orig: u32) -> Self {
        match orig {
            0 => UsernameStatus::NotPresent,
            1 => UsernameStatus::Initial,
            2 => UsernameStatus::PreorderRegistrationPending,
            3 => UsernameStatus::Preordered,
            4 => UsernameStatus::RegistrationPending,
            5 => UsernameStatus::Confirmed,
            6 => UsernameStatus::TakenOnNetwork,
            _ => UsernameStatus::NotPresent,
        }
    }
}

impl From<UsernameStatus> for u32 {
    fn from(value: UsernameStatus) -> Self {
        match value {
            UsernameStatus::NotPresent => 0,
            UsernameStatus::Initial => 1,
            UsernameStatus::PreorderRegistrationPending => 2,
            UsernameStatus::Preordered => 3,
            UsernameStatus::RegistrationPending => 4,
            UsernameStatus::Confirmed => 5,
            UsernameStatus::TakenOnNetwork => 6,
        }
    }
}

impl From<i16> for UsernameStatus {
    fn from(orig: i16) -> Self {
        match orig {
            0 => UsernameStatus::NotPresent,
            1 => UsernameStatus::Initial,
            2 => UsernameStatus::PreorderRegistrationPending,
            3 => UsernameStatus::Preordered,
            4 => UsernameStatus::RegistrationPending,
            5 => UsernameStatus::Confirmed,
            6 => UsernameStatus::TakenOnNetwork,
            _ => UsernameStatus::NotPresent,
        }
    }
}

impl From<UsernameStatus> for i16 {
    fn from(value: UsernameStatus) -> Self {
        match value {
            UsernameStatus::NotPresent => 0,
            UsernameStatus::Initial => 1,
            UsernameStatus::PreorderRegistrationPending => 2,
            UsernameStatus::Preordered => 3,
            UsernameStatus::RegistrationPending => 4,
            UsernameStatus::Confirmed => 5,
            UsernameStatus::TakenOnNetwork => 6,
        }
    }
}

