use std::mem;
use byte::BytesExt;
use hashes::{Hash, sha256};
use hashes::hex::{FromHex, ToHex};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use crate::chain::bip::dip14::{ckd_priv, ckd_pub};
use crate::chain::chain::Chain;
use crate::chain::ext::settings::Settings;
use crate::chain::params::ScriptMap;
use crate::consensus::Encodable;
use crate::crypto::byte_util::{AsBytes, BytesDecodable, clone_into_array, Zeroable};
use crate::crypto::{ECPoint, UInt160, UInt256, UInt512};
use crate::derivation::BIP32_HARD;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::index_path::IndexPath;
use crate::keys::key::IKey;
use crate::keys::KeyType;
use crate::util::address::Address;
use crate::util::base58;


#[derive(Clone, Debug, Default)]
pub struct ECDSAKey {
    pub seckey: UInt256,
    pub pubkey: Vec<u8>,
    pub compressed: bool,
    pub chaincode: UInt256,
    pub fingerprint: u32,
    pub is_extended: bool,
}

impl IKey for ECDSAKey {
    fn r#type(&self) -> KeyType {
        KeyType::ECDSA
    }

    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        self.compact_sign(UInt256::from_bytes(data, &mut 0).unwrap())
    }

    fn verify(&self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        todo!()
    }

    fn public_key_data(&mut self) -> Vec<u8> {
        //if self.pubkey.is_empty() && !self.seckey.is_zero()
        if self.pubkey.is_empty() && self.has_private_key() {
            // TODO: impl SecureAllocator
            //NSMutableData *d = [NSMutableData secureDataWithLength:self.compressed ? 33 : 65];
            // let mut d = Vec::<u8>::with_capacity(if self.compressed { 33 } else { 65 });
            let seckey = secp256k1::SecretKey::from_slice(self.seckey.as_bytes()).unwrap();
            let pubkey = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &seckey);
            self.pubkey = if self.compressed {
                pubkey.serialize().to_vec()
            } else {
                pubkey.serialize_uncompressed().to_vec()
            };
           self.pubkey.clone()
        } else {
            assert!(false, "Public key data should exist");
            vec![]
        }
    }

    fn extended_private_key_data(&self) -> Option<Vec<u8>> {
        if !self.is_extended {
            None
        } else if let Some(private_key_data) = self.private_key_data() {
            // TODO: secure data
            //NSMutableData *data = [NSMutableData secureData];
            let mut writer = Vec::<u8>::new();
            self.fingerprint.enc(&mut writer);
            self.chaincode.enc(&mut writer);
            private_key_data.enc(&mut writer);
            Some(writer)
        } else {
            None
        }
    }

    fn extended_public_key_data(&mut self) -> Option<Vec<u8>> {
        if !self.is_extended {
            None
        } else {
            let mut writer = Vec::<u8>::new();
            self.fingerprint.enc(&mut writer);
            self.chaincode.enc(&mut writer);
            self.public_key_data().enc(&mut writer);
            // assert!(writer.len() >= 4 + std:: sizeof(UInt256) + sizeof(DSECPoint), @"extended public key is wrong size");
            Some(writer)
        }
    }

    fn serialized_private_key_for_chain(&self, script: &ScriptMap) -> String {
        //if (uint256_is_zero(_seckey)) return nil;
        //NSMutableData *d = [NSMutableData secureDataWithCapacity:sizeof(UInt256) + 2];
        let mut writer = Vec::<u8>::new();
        script.privkey.enc(&mut writer);
        self.seckey.enc(&mut writer);
        if self.compressed {
            b'\x01'.enc(&mut writer);
        }
        base58::check_encode_slice(&writer)
    }
    fn forget_private_key(&mut self) {

    }

    fn public_derive_to_256bit_derivation_path_with_offset(&mut self, derivation_path: &dyn IDerivationPath, offset: usize) -> Option<&dyn IKey> {
        // assert!(derivation_path.length() > offset, "derivationPathOffset must be smaller that the derivation path length");
        let chain = self.chaincode;
        let pubkey = ECPoint::from_bytes_force(&self.public_key_data());
        todo!()
        // for i in 0..self.length() - 1 {
        //     ckd_priv_256(secret, chain, &self.index_at_position(i), self.hardened_at_position(i));
        // }

        // DSECPoint pubKey = *(const DSECPoint *)((const uint8_t *)self.publicKeyData.bytes);
        // for (NSInteger i = derivationPathOffset; i < [derivationPath length] - 1; i++) {
        //     UInt256 derivation = [derivationPath indexAtPosition:i];
        //     BOOL isHardenedAtPosition = [derivationPath isHardenedAtPosition:i];
        //     CKDpub256(&pubKey, &chain, derivation, isHardenedAtPosition);
        // }
        // NSData *publicKeyData = [NSData dataWithBytes:&pubKey length:sizeof(pubKey)];
        // uint32_t fingerprint = publicKeyData.hash160.u32[0];
        //
        // UInt256 derivation = [derivationPath indexAtPosition:[derivationPath length] - 1];
        // BOOL isHardenedAtPosition = [derivationPath isHardenedAtPosition:[derivationPath length] - 1];
        //
        // CKDpub256(&pubKey, &chain, derivation, isHardenedAtPosition);
        //
        // publicKeyData = [NSData dataWithBytes:&pubKey length:sizeof(pubKey)];
        // DSECDSAKey *childKey = [DSECDSAKey keyWithPublicKeyData:publicKeyData];
        // childKey.chaincode = chain;
        // childKey.fingerprint = fingerprint;
        // childKey.isExtended = TRUE;
        //
        // NSAssert(childKey, @"Public key should be created");
        // return childKey;

    }
}

impl ECDSAKey {

    pub fn init_with_compact_sig(compact_sig: &Vec<u8>, message_digest: UInt256) -> Option<ECDSAKey> {
        // assert!(compact_sig, "ECDSAKey::init_with_compact_sig {null}");
        if compact_sig.len() != 65 {
            return None;
        }
        let compressed = compact_sig[0] - 27 >= 4;
        let recid = RecoveryId::from_i32(((compact_sig[0] - 27) % 4) as i32).unwrap();
        RecoverableSignature::from_compact(&compact_sig[1..], recid)
            .and_then(|sig| Secp256k1::new().recover_ecdsa(&Message::from(message_digest), &sig)
                .map(|pk| ECDSAKey::with_pubkey_compressed(pk, compressed)))
            .ok()
    }

    pub fn init_with_seed_data(data: &Vec<u8>) -> Option<Self> {
        let i = UInt512::bip32_seed_key(data);
        secp256k1::SecretKey::from_slice(&i.0[..32])
            .ok()
            .map(|seckey| Self::with_seckey_and_chaincode(seckey, UInt256(clone_into_array(&i.0[32..])), true))
    }

    pub fn init_with_secret(secret: UInt256, compressed: bool) -> Option<Self> {
        secp256k1::SecretKey::from_slice(secret.as_bytes())
            .ok()
            .map(|seckey| Self::with_seckey(seckey, compressed))
    }

    pub fn init_with_extended_private_key_data(data: &Vec<u8>) -> Option<Self> {
        // assert_eq!(data.len(), ECDSA_EXTENDED_SECRET_KEY_SIZE, "Key size is incorrect");
        Self::init_with_secret(data.read_with::<UInt256>(&mut 36, byte::LE).unwrap(), true)
            .map(|mut s| {
                let offset = &mut 0;
                s.fingerprint = data.read_with::<u32>(offset, byte::LE).unwrap();
                s.chaincode = data.read_with::<UInt256>(offset, byte::LE).unwrap();
                s.is_extended = true;
                s
            })
    }

    pub fn init_with_extended_public_key_data(data: &Vec<u8>) -> Option<Self> {
        Self::init_with_public_key(data[36..].to_vec())
            .map(|mut s| {
                let offset = &mut 0;
                s.fingerprint = data.read_with::<u32>(offset, byte::LE).unwrap();
                s.chaincode = data.read_with::<UInt256>(offset, byte::LE).unwrap();
                s.is_extended = true;
                s
            })
    }

    pub fn init_with_private_key(private_key_string: &String, chain: &Chain) -> Option<Self> {
        if private_key_string.is_empty() {
            return None;
        }
        // mini private key format
        if (private_key_string.len() == 30 || private_key_string.len() == 22) && private_key_string.starts_with('L') {
            return Address::is_valid_dash_address_for_script_map(&private_key_string, chain.script())
                .then_some(Self::with_seckey(secp256k1::SecretKey::from_hashed_data::<sha256::Hash>(private_key_string.as_bytes()), false))
        }
        let data = match base58::from_check(private_key_string.as_str()) {
            Ok(data) if data.len() != 28 => data,
            _ => match base58::from(private_key_string.as_str()) {
                Ok(data) => {
                    if data.len() < mem::size_of::<UInt256>() || data.len() > mem::size_of::<UInt256>() + 2 {
                        Vec::from_hex(private_key_string.as_str()).unwrap()
                    } else {
                        data
                    }
                },
                _ => vec![]
            }
        };
        if (data.len() == mem::size_of::<UInt256>() + 1 || data.len() == mem::size_of::<UInt256>() + 2) && data[0] == chain.script().privkey {
            secp256k1::SecretKey::from_slice(&data[1..])
                .ok()
                .map(|seckey| ECDSAKey::with_seckey(seckey, data.len() == mem::size_of::<UInt256>() + 2))
        } else if data.len() == mem::size_of::<UInt256>() {
            secp256k1::SecretKey::from_slice(&data)
                .ok()
                .map(|seckey| ECDSAKey::with_seckey(seckey, false))
        } else {
            None
        }
    }

    pub fn init_with_public_key(public_key: Vec<u8>) -> Option<Self> {
        assert!(!public_key.is_empty(), "public_key is empty");
        if public_key.len() != 33 && public_key.len() != 65 {
            None
        } else {
            secp256k1::PublicKey::from_slice(&public_key)
                .ok()
                .map(|pubkey| ECDSAKey::with_pubkey_compressed(pubkey, public_key.len() == 33))
        }
    }

    pub fn secret_key_string(&self) -> String {
        if self.has_private_key() {
            self.seckey.0.to_hex()
        } else {
            String::new()
        }
    }

    pub fn has_private_key(&self) -> bool {
        !self.seckey.is_zero()
    }

    /// Pieter Wuille's compact signature encoding used for bitcoin message signing
    /// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
    pub fn compact_sign(&self, message_digest: UInt256) -> Vec<u8> {
        // is_zero()
        if self.seckey.is_zero() {
            println!("Can't sign with a public key");
            return vec![];
        }
        let secp = secp256k1::Secp256k1::new();
        let msg = Message::from_slice(&message_digest.0).unwrap();
        let seckey = secp256k1::SecretKey::from_slice(self.seckey.as_bytes()).unwrap();
        let rec_sig = secp.sign_ecdsa_recoverable(&msg, &seckey);
        let (rec_id, bytes) = rec_sig.serialize_compact();
        let sig = Vec::with_capacity(65);
        sig[0] = 27 + rec_id.to_i32() as u8  + if self.compressed { 4 } else { 0 };
        sig[1..].clone_from_slice(&bytes);
        sig
    }

    pub fn hash160(&mut self) -> UInt160 {
        UInt160::hash160(&self.public_key_data())
    }

    pub fn key_recovered_from_compact_sig(compact_sig: &Vec<u8>, message_digest: UInt256) -> Option<Self> {
        Self::init_with_compact_sig(compact_sig, message_digest)
    }

    pub fn key_with_private_key(private_key_string: &String, chain: &Chain) -> Option<Self> {
        Self::init_with_private_key(private_key_string, chain)
    }

    pub fn key_with_public_key_data(data: &Vec<u8>) -> Option<Self> {
        assert!(!data.is_empty());
        if data.len() != 33 && data.len() != 65 {
            None
        } else {
            secp256k1::PublicKey::from_slice(data)
                .ok()
                .map(|pubkey| ECDSAKey::with_pubkey_compressed(pubkey, data.len() == 33))
        }
    }

    pub fn serialized_auth_private_key_from_seed(seed: &Vec<u8>, chain: &Chain) -> String {
        let i = UInt512::bip32_seed_key(seed);
        let mut secret = UInt256(clone_into_array(&i.0[..32]));
        let mut chain_hash = UInt256(clone_into_array(&i.0[32..]));
        // path m/1H/0 (same as copay uses for bitauth)
        ckd_priv(secret, chain_hash, 1 | BIP32_HARD);
        ckd_priv(secret, chain_hash, 0);
        let mut writer = &mut Vec::<u8>::new();
        chain.script().privkey.enc(writer);
        secret.enc(writer);
        b'\x01'.enc(writer); // specifies compressed pubkey format
        base58::check_encode_slice(&writer)
    }

    pub fn key_with_secret(data: &Vec<u8>, compressed: bool) -> Option<Self> {
        secp256k1::SecretKey::from_slice(data)
            .ok()
            .map(|seckey| Self::with_seckey(seckey, compressed))
    }

    fn with_pubkey_compressed(pubkey: secp256k1::PublicKey, compressed: bool) -> ECDSAKey {
        Self { pubkey: if compressed { pubkey.serialize().to_vec() } else { pubkey.serialize_uncompressed().to_vec() }, compressed, ..Default::default() }
    }

    fn with_seckey(seckey: secp256k1::SecretKey, compressed: bool) -> Self {
        Self { seckey: UInt256(seckey.secret_bytes()), compressed, ..Default::default() }
    }

    fn with_seckey_and_chaincode(seckey: secp256k1::SecretKey, chaincode: UInt256, compressed: bool) -> Self {
        Self { seckey: UInt256(seckey.secret_bytes()), chaincode, compressed, ..Default::default() }
    }

    pub fn public_key_from_extended_public_key_data(data: &Vec<u8>, index_path: &IndexPath<u32>) -> Option<Vec<u8>> {
        if data.len() < 4 + mem::size_of::<UInt256>() + mem::size_of::<ECPoint>() {
            assert!(false, "Extended public key is wrong size");
            return None;
        }
        let mut offset = &mut 4;
        let mut chain = UInt256::from_bytes(data, offset).unwrap();
        let mut k = ECPoint::from_bytes(data, offset).unwrap();
        // TODO: check if is valid
        index_path.indexes.iter().for_each(|&i| ckd_pub(k, chain, i));
        Some(k.as_bytes().to_vec())
    }


}
