#[derive(Debug, Default)]
pub enum StateType {
    #[default]
    Initial = 1,
    Replace = 2,
    Delete = 4,
    Update = 8,
}

impl From<StateType> for u32 {
    fn from(value: StateType) -> Self {
        match value {
            StateType::Initial => 1,
            StateType::Replace => 2,
            StateType::Delete => 4,
            StateType::Update => 8,
        }
    }
}
