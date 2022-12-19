use byte::{BytesExt, LE, Result, TryRead};
use byte::ctx::Endian;
use std::{mem, slice};
use std::net::IpAddr;
use hashes::{Hash, hash160, sha256, sha256d};
use secp256k1::rand::{Rng, thread_rng};
use crate::consensus::{Decodable, Encodable, ReadExt, WriteExt};
use crate::hashes::{hex::{FromHex, ToHex}, hex};

pub const MN_ENTRY_PAYLOAD_LENGTH: usize = 151;

#[inline]
pub fn merkle_root_from_hashes(hashes: Vec<UInt256>) -> Option<UInt256> {
    let length = hashes.len();
    let mut level = hashes.clone();
    if length == 0 { return None; }
    if length == 1 { return Some(hashes[0]); }
    while level.len() != 1 {
        let len = level.len();
        let capacity = (0.5 * len as f64).round();
        let mut higher_level: Vec<UInt256> = Vec::with_capacity(capacity as usize);
        for i in (0..len).step_by(2) {
            let mut buffer: Vec<u8> = Vec::with_capacity(64);
            let left = level[i];
            left.enc(&mut buffer);
            if level.len() - i > 1 {
                level[i+1]
            } else {
                left
            }.enc(&mut buffer);
            higher_level.push(UInt256::sha256d(&buffer));
        }
        level = higher_level;
    }
    Some(level[0])
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

pub trait AsBytesVec {
    fn as_bytes_vec(&self) -> &Vec<u8>;
}

pub trait Reversable {
    fn reversed(&mut self) -> Self;
}

pub trait Zeroable {
    fn is_zero(&self) -> bool;
}

pub trait MutDecodable<'a, T: TryRead<'a, Endian>> {
    fn from_mut(bytes: *mut u8) -> Option<T>;
}
pub trait ConstDecodable<'a, T: TryRead<'a, Endian>> {
    fn from_const(bytes: *const u8) -> Option<T>;
}
pub trait BytesDecodable<'a, T: TryRead<'a, Endian>> {
    fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<T>;
}
// TODO: migrate to bigger slices [u32; N]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt128(pub [u8; 16]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt160(pub [u8; 20]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt256(pub [u8; 32]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt384(pub [u8; 48]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt512(pub [u8; 64]);
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UInt768(pub [u8; 96]);


#[macro_export]
macro_rules! impl_bytes_decodable {
    ($var_type: ident) => {
        impl<'a> BytesDecodable<'a, $var_type> for $var_type {
            fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<Self> {
                bytes.read_with(offset, LE).ok()
            }
        }
    }
}
#[macro_export]
macro_rules! impl_bytes_decodable_lt {
    ($var_type: ident) => {
        impl<'a> BytesDecodable<'a, $var_type<'a>> for $var_type<'a> {
            fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> Option<Self> {
                bytes.read_with(offset, LE).ok()
            }
        }
    }
}

#[macro_export]
macro_rules! impl_decodable {
    ($var_type: ident, $byte_len: expr) => {
        impl_bytes_decodable!($var_type);

        impl<'a> ConstDecodable<'a, $var_type> for $var_type {
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            fn from_const(bytes: *const u8) -> Option<Self> {
                let safe_bytes = unsafe { slice::from_raw_parts(bytes, $byte_len) };
                safe_bytes.read_with::<Self>(&mut 0, LE).ok()
            }
        }
        impl<'a> MutDecodable<'a, $var_type> for $var_type {
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            fn from_mut(bytes: *mut u8) -> Option<Self> {
                let safe_bytes = unsafe { slice::from_raw_parts_mut(bytes, $byte_len) };
                safe_bytes.read_with::<Self>(&mut 0, LE).ok()
            }
        }
    }
}

#[macro_export]
macro_rules! define_try_read_to_big_uint {
    ($uint_type: ident, $byte_len: expr) => {
        impl<'a> TryRead<'a, Endian> for $uint_type {
            fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
                let offset = &mut 0;
                let mut data: [u8; $byte_len] = [0u8; $byte_len];
                for _i in 0..$byte_len {
                    let index = offset.clone();
                    let chunk = bytes.read_with::<u8>(offset, endian)?;
                    data[index] = chunk;
                }
                Ok(($uint_type(data), $byte_len))
            }
        }
    }
}

#[macro_export]
macro_rules! define_bytes_to_big_uint {
    ($uint_type: ident, $byte_len: expr) => {
        define_try_read_to_big_uint!($uint_type, $byte_len);
        impl std::default::Default for $uint_type {
            fn default() -> Self {
                let mut data: [u8; $byte_len] = [0u8; $byte_len];
                for i in 0..$byte_len {
                    data[i] = 0;
                }
                Self(data)
            }
        }

        impl std::fmt::Display for $uint_type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.0.to_hex())?;
                Ok(())
            }
        }
        impl std::fmt::Debug for $uint_type {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.0.to_hex())?;
                Ok(())
            }
        }
        impl Encodable for $uint_type {
            #[inline]
            fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> std::result::Result<usize, std::io::Error> {
                writer.emit_slice(&self.as_bytes())?;
                Ok($byte_len)
            }
        }

        impl Decodable for $uint_type {
            #[inline]
            fn consensus_decode<D: std::io::Read>(mut d: D) -> std::result::Result<Self, crate::consensus::encode::Error> {
                let mut ret = [0; $byte_len];
                d.read_slice(&mut ret)?;
                Ok($uint_type(ret))
            }
        }

        impl Reversable for $uint_type {
            fn reversed(&mut self) -> Self {
                self.0.reverse();
                *self
            }
        }
        impl FromHex for $uint_type {
            fn from_byte_iter<I>(iter: I) -> std::result::Result<Self, hex::Error>
                where I: Iterator<Item=std::result::Result<u8, hashes::hex::Error>> +
                ExactSizeIterator +
                DoubleEndedIterator {
                if iter.len() == $byte_len {
                    let mut ret = [0; $byte_len];
                    for (n, byte) in iter.enumerate() {
                        ret[n] = byte?;
                    }
                    Ok($uint_type(ret))
                } else {
                    Err(hex::Error::InvalidLength(2 * $byte_len, 2 * iter.len()))
                }
            }
        }

        impl Zeroable for $uint_type {
            fn is_zero(&self) -> bool {
                for i in 0..$byte_len {
                    if self.0[i] > 0 {
                        return false;
                    }
                }
                true
            }
        }

        impl $uint_type {
            pub const MIN: Self = $uint_type([0; $byte_len]);
            pub const MAX: Self = $uint_type([!0; $byte_len]);
        }

        impl AsBytes for $uint_type {
            fn as_bytes(&self) -> &[u8] {
                &self.0[..]
            }
        }
        impl AsBytesVec for $uint_type {
            fn as_bytes_vec(&self) -> &Vec<u8> {
                &self.0[..].to_vec()
            }
        }
        impl_decodable!($uint_type, $byte_len);
    }
}


impl_decodable!(u8, 1);
impl_decodable!(u16, 2);
impl_decodable!(u32, 4);
impl_decodable!(u64, 8);
impl_decodable!(usize, mem::size_of::<usize>());
impl_decodable!(i8, 1);
impl_decodable!(i16, 2);
impl_decodable!(i32, 4);
impl_decodable!(i64, 8);
impl_decodable!(isize, mem::size_of::<isize>());


define_bytes_to_big_uint!(UInt128, 16);
define_bytes_to_big_uint!(UInt160, 20);
define_bytes_to_big_uint!(UInt256, 32);
define_bytes_to_big_uint!(UInt384, 48);
define_bytes_to_big_uint!(UInt512, 64);
define_bytes_to_big_uint!(UInt768, 96);

pub trait Random {
    fn random() -> dyn Sized;
}

impl Random for UInt256 {
    fn random() -> UInt256 {
        let mut data: [u8; 32] = [0u8; 32];
        for i in 0..32 {
            data[i] = thread_rng().gen();
        }
        UInt256(data)
    }
}
pub const fn merge<const N: usize>(mut buf: [u8; N], bytes: &[u8]) -> [u8; N] {
    let mut i = 0;
    while i < bytes.len() {
        buf[i] = bytes[i];
        i += 1;
    }
    buf
}


// From<i32> for UInt128
impl UInt128 {
    pub fn ip_address_from_i32(value: i32) -> Self {
        let mut buffer = [0u8; 16];
        buffer[0..8].fill(0);
        buffer[8..10].fill(0xff);
        buffer.emit_i32(value).unwrap();

        println!("{:?}", buffer);
        UInt128(buffer)
    }

    pub fn ip_address_to_i32(&self) -> i32 {
        // todo: check impl
        // if (p.address.u64[0] != 0 || p.address.u32[2] != CFSwapInt32HostToBig(0xffff)) continue; // skip IPv6 for now
        // CFSwapInt32BigToHost(p.address.u32[3])
        i32::from_be_bytes(self.0[12..] as [u8; 4])
    }

    pub fn to_ip_addr(&self) -> IpAddr {
        IpAddr::from(self.0)
    }
}

impl UInt256 {
    pub fn sha256(data: &[u8]) -> Self {
        UInt256(sha256::Hash::hash(data).into_inner())
    }
    pub fn sha256d(data: &[u8]) -> Self {
        UInt256(sha256d::Hash::hash(data).into_inner())
    }
}

impl UInt160 {
    pub fn hash160(data: &[u8]) -> Self {
        UInt160(hash160::Hash::hash(data).into_inner())
    }
}
