use std::collections::HashMap;
use crate::platform::document::document::{DocumentKey, DocumentValue};
use crate::platform::document::state_type::StateType;

pub struct State {
    pub document_state_type: StateType,
    pub data_change_dictionary: HashMap<DocumentKey, DocumentValue>,
}

impl State {

    pub fn document_state_with_data_dictionary(data_dictionary: HashMap<DocumentKey, DocumentValue>) -> Self {
        Self {
            document_state_type: if data_dictionary.contains_key("$updatedAt") && !data_dictionary.contains_key("$createdAt") {
                StateType::Replace
            } else {
                StateType::Initial
            },
            data_change_dictionary: data_dictionary
        }
    }

    pub fn document_state_with_data_dictionary_of_type(data_dictionary: HashMap<String, DocumentValue>, state_type: StateType) -> Self {
        Self {
            document_state_type: state_type,
            data_change_dictionary: data_dictionary
        }
    }

}
