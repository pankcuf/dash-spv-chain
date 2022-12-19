use byte::ctx::Endian;
use byte::{BytesExt, TryRead};

pub enum ObjectType {
    Unknown = 0,
    Proposal = 1,
    Trigger = 2,
    /// deprecated
    Watchdog = 3
}

impl From<u32> for ObjectType {
    fn from(orig: u32) -> Self {
        match orig {
            0 => ObjectType::Unknown,
            1 => ObjectType::Proposal,
            2 => ObjectType::Trigger,
            3 => ObjectType::Watchdog,
            _ => ObjectType::Unknown,
        }
    }
}

impl From<ObjectType> for u32 {
    fn from(value: ObjectType) -> Self {
        match value {
            ObjectType::Unknown => 0,
            ObjectType::Proposal => 1,
            ObjectType::Trigger => 2,
            ObjectType::Watchdog => 3,
        }
    }
}

impl<'a> TryRead<'a, Endian> for ObjectType {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let orig = bytes.read_with::<u32>(&mut 0, endian).unwrap();
        let data = ObjectType::from(orig);
        Ok((data, std::mem::size_of::<u32>()))
    }
}
