// Special Transaction
// https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md

#[derive(Debug, Default, PartialEq)]
pub enum Type {
    #[default]
    DataContract = 0,
    Documents = 1,
    IdentityRegistration = 2,
    IdentityTopUp = 3,
    IdentityUpdateKey = 4,
    IdentityCloseAccount = 5,
}

impl From<Type> for u8 {
    fn from(value: Type) -> Self {
        match value {
            Type::DataContract => 0,
            Type::Documents => 1,
            Type::IdentityRegistration => 2,
            Type::IdentityTopUp => 3,
            Type::IdentityUpdateKey => 4,
            Type::IdentityCloseAccount => 5,
        }
    }
}

impl From<&Type> for u8 {
    fn from(value: &Type) -> Self {
        match value {
            Type::DataContract => 0,
            Type::Documents => 1,
            Type::IdentityRegistration => 2,
            Type::IdentityTopUp => 3,
            Type::IdentityUpdateKey => 4,
            Type::IdentityCloseAccount => 5,
        }
    }
}

impl From<u8> for Type {
    fn from(value: u8) -> Self {
        match value {
            0 => Type::DataContract,
            1 => Type::Documents,
            2 => Type::IdentityRegistration,
            3 => Type::IdentityTopUp,
            4 => Type::IdentityUpdateKey,
            5 => Type::IdentityCloseAccount,
            _ => Type::DataContract
        }
    }
}

impl serde::Serialize for Type {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.into())
    }
}
impl<'de> serde::Deserialize<'de> for Type {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u8::deserialize(deserializer).map(Type::from)
    }
}

