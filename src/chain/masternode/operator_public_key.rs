use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use crate::crypto::UInt384;

#[derive(Copy, Clone, Debug, Default, Ord, PartialOrd, Eq, FromSqlRow, AsExpression)]
#[diesel(sql_type = diesel::sql_types::Binary)]
pub struct OperatorPublicKey {
    pub data: UInt384,
    pub version: u16,
}

impl PartialEq for OperatorPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self == other || (self.data == other.data && self.version == other.version)
    }
}

impl<'a> TryRead<'a, Endian> for OperatorPublicKey {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let data = bytes.read_with::<UInt384>(offset, endian).unwrap();
        let version = bytes.read_with::<u16>(offset, endian).unwrap();
        Ok((OperatorPublicKey { data, version }, *offset))
    }
}
