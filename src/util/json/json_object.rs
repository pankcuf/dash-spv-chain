pub trait JsonObject {
    fn from_json<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, serde_json::Error> {
        serde_json::from_value(value)
    }
}
