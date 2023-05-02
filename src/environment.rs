use bip39::Language;
use ring::rand::SystemRandom;
use crate::resource::bundle::Bundle;

#[derive(Debug)]
pub struct Environment {
    pub system_random: SystemRandom,
    pub resource_bundle: Bundle,
    pub language: Language,
}

impl Default for Environment {
    fn default() -> Self {
        Self {
            system_random: SystemRandom::new(),
            resource_bundle: Bundle::default(),
            language: Language::English
        }
    }
}

impl<'a> Default for &'a Environment {
    fn default() -> Self {
        &Environment::default()
    }
}

impl Environment {
    pub fn new(language: Language) -> Self {
        Self {
            language,
            resource_bundle: Bundle {},
            system_random: SystemRandom::new()

        }
    }
    // true if this is a "watch only" wallet with no signing ability
    pub fn watch_only() -> bool {
        false
    }

    pub fn load_words_from_bundle(&self) -> Vec<String> {
        self.resource_bundle.load_words()
    }
}
