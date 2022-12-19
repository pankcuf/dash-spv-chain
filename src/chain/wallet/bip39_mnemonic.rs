use std::collections::{HashMap, HashSet};
use crate::chain::wallet::bip39_language::Bip39Language;

// pub const BIP39_CREATION_TIME: u64 = 1425492298;
pub const BIP39_CREATION_TIME: u32 = 1425492298;
//1546810296.0 <- that would be block 1M
pub const BIP39_WALLET_UNKNOWN_CREATION_TIME: u64 = 0;

pub struct BIP39Mnemonic {
    pub words: Vec<String>,
    pub default_language: Bip39Language,

    all_words: HashSet<String>,
    words_for_languages: HashMap<Bip39Language, Vec<String>>,
}


impl BIP39Mnemonic {
    pub fn available_languages(&self) -> Vec<Bip39Language> {
        vec![
            Bip39Language::English,
            Bip39Language::French,
            Bip39Language::Italian,
            Bip39Language::Spanish,
            Bip39Language::ChineseSimplified,
            Bip39Language::Korean,
            Bip39Language::Japanese
        ]
    }

    pub fn normalize_phrase(phrase: &String) -> Option<String> {
        todo!()
    }

    pub fn derive_key_from_phrase(phrase: &String, passphrase: Option<String>) -> Vec<u8> {
        todo!()
    }

}
