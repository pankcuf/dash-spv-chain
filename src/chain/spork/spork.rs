use bitcoin_hashes::{Hash, hash160, sha256d};
use bitcoin_hashes::hex::{FromHex, ToHex};
use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, LE, TryRead};
use secp256k1::Secp256k1;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::{UInt160, UInt256};
use crate::util::base58;
use crate::chain::chain::Chain;
use crate::chain::constants::DASH_MESSAGE_MAGIC;
use crate::chain::params::{DASH_PRIVKEY, DASH_PUBKEY_ADDRESS, DASH_PUBKEY_ADDRESS_TEST};
use crate::chain::spork;
use crate::chain::spork::Identifier;
use crate::keys::ecdsa_key::ECDSAKey;
use crate::util::ECDSAKey;

pub struct Spork {
    pub identifier: Identifier,
    pub is_valid: bool,
    pub time_signed: u64,
    pub value: u64,
    pub signature: Vec<u8>,
    pub chain: &'static Chain,
}

impl Spork {

    pub fn is_equal_to_spork(&self, spork: &Spork) -> bool {
        self.chain == spork.chain &&
            self.identifier == spork.identifier &&
            self.value == spork.value &&
            self.time_signed == spork.time_signed &&
            self.is_valid == self.is_valid
    }

    pub fn key(&self) -> Option<&str> {
        if let Some(value) = self.chain.params.spork_params.public_key_hex_string {
            return Some(value);
        }
        if let Some(value) = self.chain.params.spork_params.private_key_base58_string {
            if let Some(private_key) = ECDSAKey::init_with_private_key(value, &self.chain) {
                return Some(private_key.public_key.to_hex().as_str());
            }
        }
        None
    }

    /// starting in 12.3 sporks use addresses instead of public keys
    pub fn address(&self) -> &str {
        self.chain.params.spork_params.address
    }


    fn check_signature_70208_method(&self, signature: Vec<u8>) -> bool {
        let string_message = format!("{:?}{}{}", self.identifier, self.value, self.time_signed);
        let mut buffer: Vec<u8> = Vec::new();
        DASH_MESSAGE_MAGIC.enc(&mut buffer);
        string_message.enc(&mut buffer);
        let message_digest = UInt256::sha256d(&buffer);
        let message_public_key = ECDSAKey::init_with_compact_sig(signature, message_digest);
        let spork_public_key = ECDSAKey::init_with_public_key(Vec::from_hex(self.key().unwrap()).unwrap());
        spork_public_key.unwrap().public_key == message_public_key.unwrap().public_key
    }


    pub fn check_signature(&self, signature: Vec<u8>) -> bool {
        if self.chain.params.protocol_version < 70209 {
            self.checkSignature70208Method(signature)
        } else {
            let msg_public_key = ECDSAKey::init_with_compact_sig(signature, self.calculate_spork_hash()).unwrap();
            let spork_address = msg_public_key.public_key;
            // todo: impl SecureAllocator
            //Secp256k1::
            let d = SecureBox::new(160 / 8 + 1);
            //NSMutableData *d = [NSMutableData secureDataWithCapacity:160 / 8 + 1];
            // let d = Vec::with_capacity(21);
            let version = if self.chain.params.chain_type.is_mainnet() {
                DASH_PUBKEY_ADDRESS
            } else {
                DASH_PUBKEY_ADDRESS_TEST
            };
            let hash160 = UInt160::hash160(&spork_address);
            let mut buffer: Vec<u8> = Vec::with_capacity(21);
            version.enc(&mut buffer);
            hash160.enc(&mut buffer);

            // [NSString base58checkWithData:buffer];
            let address = base58::check_encode_slice(&buffer);
            self.address() == address.as_str() ||
                (!self.chain.spork_manager().sporks_updated_signatures() && self.check_signature_70208_method(signature.clone()))
        }
    }

    pub fn calculate_spork_hash(&self) -> UInt256 {
        let mut buffer: Vec<u8> = Vec::with_capacity(4 + 8 + 8);
        self.identifier.enc(&mut buffer);
        self.value.enc(&mut buffer);
        self.time_signed.enc(&mut buffer);
        UInt256::sha256d(&buffer)
    }

    pub fn init_from_message(bytes: &[u8], chain: &Chain) -> Self {
        let offset = &mut 0;
        let identifier = bytes.read_with::<Identifier>(offset, LE).unwrap();
        let value = bytes.read_with::<u64>(offset, LE).unwrap();
        let time_signed = bytes.read_with::<u64>(offset, LE).unwrap();
        let signature_length = bytes.read_with::<VarInt>(offset, LE)?.0 as usize;
        let signature_bytes: &[u8] = bytes.read_with(offset, Bytes::Len(signature_length))?;
        let signature = signature_bytes.to_vec();
        let mut spork = Spork {
            identifier,
            is_valid: false,
            time_signed,
            value,
            signature,
            chain
        };
        spork.is_valid = spork.check_signature(signature.clone());
        spork
    }
}

// impl<'a> TryRead<'a, Endian> for Spork {
//     fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
//         let offset = &mut 0;
//         let identifier = bytes.read_with::<Identifier>(offset, endian).unwrap();
//         let value = bytes.read_with::<u64>(offset, endian).unwrap();
//         let time_signed = bytes.read_with::<u64>(offset, endian).unwrap();
//         let signature_length = bytes.read_with::<VarInt>(offset, LE)?.0 as usize;
//         let signature: &[u8] = bytes.read_with(offset, Bytes::Len(signature_length))?;
//         let spork = Spork {
//             identifier,
//             is_valid: false,
//             time_signed,
//             value,
//             signature: signature.to_vec(),
//             chain: None
//         };
//         Ok((spork, *offset))
//     }
// }
