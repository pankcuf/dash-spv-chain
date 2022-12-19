pub trait Mnemonic {
    fn encode_phrase(&self, data: Option<Vec<u8>>) -> Option<String>;
    /// phrase must be normalized
    fn decode_phrase(&self, data: String) -> Option<Vec<u8>>;
    /// true if word is a member of any known word list
    fn word_is_valid(&self, word: String) -> bool;
    /// true if word is a member of the word list for the current locale
    fn word_is_local(&self, word: String) -> bool;
    /// true if all words and checksum are valid, phrase must be normalized
    fn phrase_is_valid(&self, phrase: String) -> bool;
    /// minimally cleans up user input phrase, suitable for display/editing
    fn cleanup_phrase(&self, phrase: String) -> String;
    /// normalizes phrase, suitable for decode/derivation
    fn normalize_phrase(&self, phrase: Option<String>) -> Option<String>;
    /// phrase must be normalized
    fn derive_key_from_phrase(phrase: String, passphrase: Option<String>) -> Vec<u8>;
}
