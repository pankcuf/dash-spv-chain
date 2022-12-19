use crate::crypto::UInt128;

#[repr(C)]
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct SocketAddress {
    pub ip_address: UInt128, //v6, but only v4 supported
    pub port: u16,
}

impl PartialEq for SocketAddress {
    fn eq(&self, other: &Self) -> bool {
        self == other || (self.ip_address == other.ip_address && self.port == other.port)
    }
}
