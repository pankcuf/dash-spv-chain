use crate::consensus::Encodable;

pub struct NetAddress {
    pub address: u32,
    pub port: u16,
    pub services: u64,
}

impl NetAddress {
    pub fn new(address: u32, port: u16, services: u64) -> Self {
        Self { address, port, services }
    }
}

impl<'a> byte::TryWrite<byte::ctx::Endian> for NetAddress {
    fn try_write(self, bytes: &mut [u8], _endian: byte::ctx::Endian) -> byte::Result<usize> {
        let offset: &mut usize = &mut 0;
        *offset += self.services.consensus_encode(bytes).unwrap();
        *offset += b"\0\0\0\0\0\0\0\0\0\0\xFF\xFF".consensus_encode(bytes).unwrap(); // IPv4 mapped IPv6 header
        *offset += self.address.to_be_bytes().consensus_encode(bytes).unwrap();
        *offset += self.port.to_be_bytes().consensus_encode(bytes).unwrap();
        Ok(*offset)
    }
}
