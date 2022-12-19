pub enum Bip39Language {
    Default,
    English,
    French,
    Spanish,
    Italian,
    Japanese,
    Korean,
    ChineseSimplified,
    Unknown
}

impl Bip39Language {
    pub fn identifier(&self) -> &str {
        match self {
            Bip39Language::English => "en",
            Bip39Language::French => "fr",
            Bip39Language::Spanish => "es",
            Bip39Language::Korean => "ko",
            Bip39Language::Japanese => "ja",
            Bip39Language::ChineseSimplified => "zh-Hans",
            Bip39Language::Italian => "it",
            _ => "en",
        }
    }
}
