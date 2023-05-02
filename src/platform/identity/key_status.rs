
#[derive(Debug, Default)]
pub enum KeyStatus {
    #[default]
    Unknown = 0,
    Registered = 1,
    Registering = 2,
    NotRegistered = 3,
    Revoked = 4,
}

impl From<i16> for KeyStatus {
    fn from(orig: i16) -> Self {
        match orig {
            0 => KeyStatus::Unknown,
            1 => KeyStatus::Registered,
            2 => KeyStatus::Registering,
            3 => KeyStatus::NotRegistered,
            4 => KeyStatus::Revoked,
            _ => KeyStatus::Unknown,
        }
    }
}

impl From<KeyStatus> for i16 {
    fn from(value: KeyStatus) -> Self {
        match value {
            KeyStatus::Unknown => 0,
            KeyStatus::Registered => 1,
            KeyStatus::Registering => 2,
            KeyStatus::NotRegistered => 3,
            KeyStatus::Revoked => 4
        }
    }
}
