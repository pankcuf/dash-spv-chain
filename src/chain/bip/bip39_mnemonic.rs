// use std::collections::{HashMap, HashSet};
// use crate::chain::bip::bip39_language::Bip39Language;
// use crate::chain::chain::Chain;
// use crate::environment::Environment;
//
//
// pub struct BIP39Mnemonic {
//     pub words: Vec<String>,
//     pub default_language: Bip39Language,
//
//     all_words: HashSet<String>,
//     words_for_languages: HashMap<Bip39Language, Vec<String>>,
//     environment: &'static Environment,
// }
//
//
// impl BIP39Mnemonic {
//     pub const AVAILABLE_LANGUAGES: [Bip39Language; 7] = [
//         Bip39Language::English,
//         Bip39Language::French,
//         Bip39Language::Italian,
//         Bip39Language::Spanish,
//         Bip39Language::ChineseSimplified,
//         Bip39Language::Korean,
//         Bip39Language::Japanese
//     ];
//
//     pub fn new(environment: &Environment) -> Self {
//         Self { environment, ..Default::default() }
//     }
//
//     pub fn language_identifier(&self) -> &str {
//         self.default_language.identifier()
//     }
//
//     fn load_words(&mut self) {
//         self.words = self.environment.get_words(&self.default_language);
//     }
//
//     pub fn words(&mut self) -> &Vec<String> {
//         if self.words.is_empty() {
//             self.load_words();
//         }
//         &self.words
//     }
//
//     pub fn words_for_language(&mut self, language: Bip39Language) -> &Vec<String> {
//         self.words_for_languages.get(&language).unwrap_or_else(|| {
//             let words_for_language = self.environment.get_words(&language);
//             self.words_for_languages.insert(language, words_for_language);
//             return &words_for_language;
//         })
//     }
//
//     pub fn best_fitting_language_for_words(&mut self, words: &Vec<String>) -> Bip39Language {
//         Bip39Language::from(*words.iter().fold(HashMap::<u16, Bip39Language>::new(), |mut dict, word| {
//             self.languages_of_word(word).iter().for_each(|&lang| {
//                 dict[lang.into()] = if dict.contains(lang.into()) { lang.next() } else { Bip39Language::English }
//             });
//             dict
//         }).keys().max().unwrap_or(Bip39Language::Unknown.into()))
//     }
//
//     pub fn all_words(&mut self) -> HashSet<String> {
//         if self.all_words.is_empty() {
//             self.all_words = HashSet::from(self.environment.load_words());
//         }
//         self.all_words.clone()
//     }
//
//     pub fn encode_phrase(&mut self, data: Vec<u8>) -> Option<String> {
//         if data.len() % 4 != 0 {
//             // data length must be a multiple of 32 bits
//             return None;
//         }
//         let words = self.words();
//         assert!(!words.is_empty(), "There must be words");
//         let n = words.len();
//
//         uint32_t n = (uint32_t)self.words.count, x;
//         NSMutableArray *a =
//             CFBridgingRelease(CFArrayCreateMutable(SecureAllocator(), data.length * 3 / 4, &kCFTypeArrayCallBacks));
//         NSMutableData *d = [NSMutableData secureDataWithData:data];
//         UInt256 sha256 = data.SHA256;
//
//         [d appendBytes:&sha256 length:sizeof(sha256)]; // append SHA256 checksum
//
//         for (int i = 0; i < data.length * 3 / 4; i++) {
//             x = CFSwapInt32BigToHost(*(const uint32_t *)((const uint8_t *)d.bytes + i * 11 / 8));
//             [a addObject:self.words[(x >> (sizeof(x) * 8 - (11 + ((i * 11) % 8)))) % n]];
//         }
//
//         memset(&x, 0, sizeof(x));
//         return CFBridgingRelease(CFStringCreateByCombiningStrings(SecureAllocator(), (CFArrayRef)a, CFSTR(" ")));
//
//     }
//
//
//
//     // true if word is a member of any known word list
//     pub fn word_is_valid(&self, word: &String) -> bool {
//         self.all_words.contains(word)
//     }
//     pub fn word_is_valid_in_language(&mut self, word: &String, language: Bip39Language) -> bool {
//         if language == self.default_language {
//             &self.words
//         } else {
//             &self.words_for_language(language)
//         }.contains(word)
//     }
//
//     // returns an array of languages this word belongs to
//     pub fn languages_of_word(&mut self, word: &String) -> Vec<Bip39Language> {
//         Self::AVAILABLE_LANGUAGES
//             .into_iter()
//             .filter(|&lang| lang != self.default_language && self.word_is_valid_in_language(word, lang))
//             .collect()
//     }
//
//
//     pub fn set_default_language(&mut self, language: Bip39Language) {
//         self.words.clear();
//         self.default_language = language;
//         self.load_words();
//     }
//
//     pub fn normalize_phrase(phrase: &String) -> Option<String> {
//         todo!()
//     }
//
//     pub fn derive_key_from_phrase(phrase: &String, passphrase: Option<String>) -> Vec<u8> {
//         todo!()
//     }
//
// }
