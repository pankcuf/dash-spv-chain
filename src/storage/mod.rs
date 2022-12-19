use chrono::NaiveDateTime;
use crate::platform::base::serializable_object::SerializableValue;

pub mod manager;
pub mod models;
pub mod context;

impl SerializableValue for NaiveDateTime {
    fn as_data(&self) -> &[u8] {
        self.timestamp()
    }
}
