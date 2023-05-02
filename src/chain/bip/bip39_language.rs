// #[derive(Clone, Copy)]
// pub enum Bip39Language {
//     Default,
//     English,
//     French,
//     Spanish,
//     Italian,
//     Japanese,
//     Korean,
//     ChineseSimplified,
//     Unknown
// }
//
// impl Bip39Language {
//     pub fn identifier(&self) -> &str {
//         match self {
//             Bip39Language::English => "en",
//             Bip39Language::French => "fr",
//             Bip39Language::Spanish => "es",
//             Bip39Language::Italian => "it",
//             Bip39Language::Japanese => "ja",
//             Bip39Language::Korean => "ko",
//             Bip39Language::ChineseSimplified => "zh-Hans",
//             _ => "en",
//         }
//     }
//     pub fn next(&self) -> Bip39Language {
//         match self {
//             Bip39Language::Default => Bip39Language::English,
//             Bip39Language::English => Bip39Language::French,
//             Bip39Language::French => Bip39Language::Spanish,
//             Bip39Language::Spanish => Bip39Language::Italian,
//             Bip39Language::Italian => Bip39Language::Japanese,
//             Bip39Language::Japanese => Bip39Language::Korean,
//             Bip39Language::Korean => Bip39Language::ChineseSimplified,
//             _ => Bip39Language::Default,
//         }
//     }
// }
//
// impl From<Bip39Language> for u16 {
//     fn from(value: Bip39Language) -> Self {
//         match value {
//             Bip39Language::Default => 0,
//             Bip39Language::English => 1,
//             Bip39Language::French => 2,
//             Bip39Language::Spanish => 3,
//             Bip39Language::Italian => 4,
//             Bip39Language::Japanese => 5,
//             Bip39Language::Korean => 6,
//             Bip39Language::ChineseSimplified => 7,
//             _ => 0
//         }
//     }
// }
// impl From<u16> for Bip39Language {
//     fn from(value: u16) -> Self {
//         match value {
//             0 => Bip39Language::Default,
//             1 => Bip39Language::English,
//             2 => Bip39Language::French,
//             3 => Bip39Language::Spanish,
//             4 => Bip39Language::Italian,
//             5 => Bip39Language::Japanese,
//             6 => Bip39Language::Korean,
//             7 => Bip39Language::ChineseSimplified,
//             _ => Bip39Language::Unknown
//         }
//     }
// }
