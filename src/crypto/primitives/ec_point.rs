use crate::define_bytes_to_big_uint;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ECPoint(pub [u8; 33]);
define_bytes_to_big_uint!(ECPoint, 33);
