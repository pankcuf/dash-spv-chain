#[derive(Debug, Default, Eq, Hash, PartialEq)]
pub enum ContractState {
    #[default]
    Unknown,
    NotRegistered,
    Registered,
    Registering,
}

impl ContractState {
    pub fn name(&self) -> &str {
        match self {
            ContractState::Unknown => "Unknown",
            ContractState::Registered => "Registered",
            ContractState::Registering => "Registering",
            ContractState::NotRegistered => "Not Registered",
            _ => "Other State"
        }
    }
}
