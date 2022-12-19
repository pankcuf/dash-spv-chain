#[derive(Debug, Hash)]
pub enum Error {
    Default(&'static String),
    DefaultWithCode(&'static String, u32)
}

impl Error {
    pub fn code(&self) -> u32 {
        match self {
            Error::Default(..) => 0,
            Error::DefaultWithCode(_, code) => code,
        }
    }
    pub fn message(&self) -> &String {
        match self {
            Error::Default(message) => message,
            Error::DefaultWithCode(message, _) => message,
        }
    }
}
