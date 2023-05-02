use crate::platform::document::state_type::StateType;

#[derive(Debug, Default)]
pub struct State {
    pub document_state_type: StateType,
    pub data_change_dictionary: serde_json::Value,
}

impl State {

    pub fn document_state_with_data_dictionary(data_dictionary: serde_json::Value) -> Self {
        Self {
            document_state_type: match (data_dictionary.get("$updatedAt"), data_dictionary.get("$createdAt")) {
                (Some(..), None) => StateType::Replace,
                _ => StateType::Initial
            },
            data_change_dictionary: data_dictionary
        }
    }

    pub fn document_state_with_data_dictionary_of_type(data_dictionary: serde_json::Value, state_type: StateType) -> Self {
        Self {
            document_state_type: state_type,
            data_change_dictionary: data_dictionary
        }
    }

}
