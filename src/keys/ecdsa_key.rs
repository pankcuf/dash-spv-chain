use hashes::{Hash, hash160};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use crate::chain::chain::Chain;
use crate::chain::params::{DASH_PRIVKEY, DASH_PRIVKEY_TEST};
use crate::crypto::byte_util::{AsBytes, BytesDecodable, Zeroable};
use crate::crypto::{UInt160, UInt256};
use crate::crypto::primitives::ec_point::ECPoint;
use crate::derivation::uint256_index_path::IndexPath;
use crate::keys::key::{IKey, Key};
use crate::keys::KeyType;
use crate::platform::base::serializable_object::SerializableValue;


#[derive(Debug)]
pub struct ECDSAKey {
    pub base: Key,
    pub seckey: UInt256,
    pub pubkey: Vec<u8>,
    pub compressed: bool,
    pub chaincode: UInt256,
    pub fingerprint: u32,
    pub is_extended: bool,
}

impl ECDSAKey {
    pub fn init_with_compact_sig(compact_sig: Vec<u8>, message_digest: UInt256) -> Option<ECDSAKey> {
        assert!(compact_sig, "ECDSAKey::init_with_compact_sig {null}");
        if compact_sig.len() != 65 {
            return None;
        }
        let compressed = compact_sig[0] - 27 >= 4;
        RecoverableSignature::from_compact(&compact_sig[1..], RecoveryId(((compact_sig[0] - 27) % 4) as i32))
            .and_then(|s| Self::recover_ecdsa(&message_digest.0, &s)
                .and_then(|pk| Ok(Self::with_pubkey_compressed(if compressed { pk.serialize() } else { pk.serialize_uncompressed() }.to_vec(), compressed))))
            .ok()
    }

    // pub(crate) fn init_with_compact_sig(signature: Vec<u8>, hash: UInt256) -> Option<Self> {
    //
    //     secp256k1::PublicKey::fr
    //     if (compactSig.length != 65) return nil;
    //     if (!(self = [self init])) return nil;
    //
    //     self.compressed = (((uint8_t *)compactSig.bytes)[0] - 27 >= 4) ? YES : NO;
    //
    //     NSMutableData *pubkey = [NSMutableData dataWithLength:(self.compressed ? 33 : 65)];
    //     size_t len = pubkey.length;
    //     int recid = (((uint8_t *)compactSig.bytes)[0] - 27) % 4;
    //     secp256k1_ecdsa_recoverable_signature s;
    //     secp256k1_pubkey pk;
    //
    //     if (secp256k1_ecdsa_recoverable_signature_parse_compact(_ctx, &s, (const uint8_t *)compactSig.bytes + 1, recid) &&
    //         secp256k1_ecdsa_recover(_ctx, &pk, &s, md.u8) &&
    //         secp256k1_ec_pubkey_serialize(_ctx, pubkey.mutableBytes, &len, &pk,
    //                                       (self.compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED))) {
    //     pubkey.length = len;
    //     _pubkey = pubkey;
    //     return self;
    //     }
    //
    //     return nil;
    // }
}

impl ECDSAKey {
    // Pieter Wuille's compact signature encoding used for bitcoin message signing
    // to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
    pub(crate) fn compact_sign(&self, message_digest: UInt256) -> Vec<u8> {
        if self.seckey.is_zero() {
            println!("%s: can't sign with a public key", __func__);

        }

        if (uint256_is_zero(_seckey)) {
            DSLog(@"%s: can't sign with a public key", __func__);
            return nil;
        }

        NSMutableData *sig = [NSMutableData dataWithLength:65];
        secp256k1_ecdsa_recoverable_signature s;
        int recid = 0;

        if (secp256k1_ecdsa_sign_recoverable(_ctx, &s, md.u8, _seckey.u8, secp256k1_nonce_function_rfc6979, NULL) &&
            secp256k1_ecdsa_recoverable_signature_serialize_compact(_ctx, (uint8_t *)sig.mutableBytes + 1, &recid, &s)) {
            ((uint8_t *)sig.mutableBytes)[0] = 27 + recid + (self.compressed ? 4 : 0);
        } else
        sig = nil;

        return sig;

    }
}

impl ECDSAKey {
    pub(crate) fn hash160(&self) -> UInt160 {
        UInt160::hash160(self.public_key_data())
    }
    pub(crate) fn key_recovered_from_compact_sig(compact_signature: &Vec<u8>, message_digest: UInt256) -> Self {
        todo!()
    }
    pub(crate) fn key_with_private_key(key: &String, chain: &Chain) -> Option<Self> {
        todo!()
    }
    pub(crate) fn key_with_public_key_data(data: &Vec<u8>) -> Self {
        todo!()
    }

    pub(crate) fn serialized_auth_private_key_from_seed(seed: String, chain: &Chain) -> String {
        todo!()
    }
    pub(crate) fn key_with_secret(data: &Vec<u8>, compressed: bool) -> Option<dyn IKey> {
        todo!()
    }
}

impl SerializableValue for ECDSAKey {
    fn as_data(&self) -> &[u8] {
        todo!()
    }
}

impl IKey for ECDSAKey {
    fn r#type(&self) -> &KeyType {
        &KeyType::ECDSA
    }

    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        self.compact_sign(UInt256::from_bytes(data).unwrap()).unwrap_or_else(Vec::new())
    }

    fn verify(&self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        todo!()
    }

    fn private_derive_to_path<T>(&self, index_path: &IndexPath<T>) -> Option<dyn IKey> {
        todo!()
    }

    fn public_key_data(&self) -> &Vec<u8> {
        if self.pubkey.is_empty() && !self.seckey.is_zero() {
            // TODO: impl SecureAllocator
            //NSMutableData *d = [NSMutableData secureDataWithLength:self.compressed ? 33 : 65];
            let mut d = Vec::<u8>::new();

        }
        &self.pubkey

        if (self.pubkey.length == 0 && uint256_is_not_zero(_seckey)) {
            NSMutableData *d = [NSMutableData secureDataWithLength:self.compressed ? 33 : 65];
            size_t len = d.length;
            secp256k1_pubkey pk;

            if (secp256k1_ec_pubkey_create(_ctx, &pk, _seckey.u8)) {
                secp256k1_ec_pubkey_serialize(_ctx, d.mutableBytes, &len, &pk,
                                              (self.compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED));
                if (len == d.length) self.pubkey = d;
            }
            NSAssert(self.pubkey, @"Public key data should exist");
        }
        NSAssert(self.pubkey, @"Public key data should exist");
        return self.pubkey;

    }
}

impl ECDSAKey {

    pub fn init_with_extended_private_key_data(data: &Vec<u8>) -> Option<Vec<u8>> {
        assert_eq!(data.len(), ECDSA_EXTENDED_SECRET_KEY_SIZE, "Key size is incorrect");
        if data.len() < ECDSA_EXTENDED_SECRET_KEY_SIZE {
            return None;
        }
        todo!()

        // if (!(self = [self initWithSecret:[extendedPrivateKeyData subdataWithRange:NSMakeRange(36, 32)].UInt256 compressed:YES])) return nil;
        //
        // self.fingerprint = [extendedPrivateKeyData UInt32AtOffset:0];
        // self.chaincode = [extendedPrivateKeyData UInt256AtOffset:4];
        // self.isExtended = TRUE;
        //
        // return self;
    }




    pub fn public_key_from_extended_public_key_data<T>(data: &Vec<u8>, index_path: IndexPath<T>) -> Option<Vec<u8>> {
        if data.len() < 4 + std::mem::size_of::<UInt256>() + std::mem::size_of::<ECPoint>() {
            assert!(false, "Extended public key is wrong size");
            return None;
        }
        let chain = UInt256(data[4..] as [u8; 32]);
        // let chain = UInt256::from_bytes(&data[4..], &mut 0).unwrap();
        let pubkey = UInt256::from_bytes(&data[36..], &mut 0).unwrap();
        // TODO: check if is valid
        // UInt256 chain = *(const UInt256 *)((const uint8_t *)publicKeyData.bytes + 4);
        // DSECPoint pubKey = *(const DSECPoint *)((const uint8_t *)publicKeyData.bytes + 36);
        (0..index_path.len()).for_each(|i| {
            let derivation = index_path.indexes.get(i);
            CKDPub(&pubkey, &chain, derivation);
        });
        let data = pubkey.as_bytes();
        assert!(data, "Public key should be created");
        Some(data.to_vec)
    }


    /// Pieter Wuille's compact signature encoding used for bitcoin message signing
    /// to verify a compact signature, recover a public key from the signature and verify that it matches the signer's pubkey
    pub fn compact_sign(&self, md: UInt256) -> Option<Vec<u8>> {
        if self.seckey.is_zero() {
            println!("{:?}: can't sign with a public key", self);
            return None;
        }
        let mut sig = Vec::<u8>::new();

        todo!()
        // NSMutableData *sig = [NSMutableData dataWithLength:65];
        // secp256k1_ecdsa_recoverable_signature s;
        // int recid = 0;
        //
        // if (secp256k1_ecdsa_sign_recoverable(_ctx, &s, md.u8, _seckey.u8, secp256k1_nonce_function_rfc6979, NULL) &&
        //     secp256k1_ecdsa_recoverable_signature_serialize_compact(_ctx, (uint8_t *)sig.mutableBytes + 1, &recid, &s)) {
        //     ((uint8_t *)sig.mutableBytes)[0] = 27 + recid + (self.compressed ? 4 : 0);
        // } else
        // sig = nil;
        //
        // return sig;
        Some(sig)
    }

    pub fn init_with_private_key(private_key_string: &str, chain: &Chain) -> Option<Self> {
        let private_key_len = private_key_string.len();
        if private_key_len == 0 {
            return None;
        }
        // mini private key format
        if (private_key_len == 30 || private_key_len == 22) && private_key_string.starts_with('L') {
            if !is_valid_dash_private_key_on_chain(private_key_string, chain) {
                return None;
            }
            return Some(ECDSAKey { seckey: UInt256::sha256(private_key_string.as_bytes()), compressed: false, ..Default::default() });
        }

        let version = if chain.params.chain_type.is_mainnet() {
            DASH_PRIVKEY
        } else {
            DASH_PRIVKEY_TEST
        };



        if let Some(data) = base58::from_check(private_key_string) {

        } else {

        }

        match secp256k1::SecretKey::from_str(private_key_string) {
            Ok(data) => {

            },
            Err(err) => {
                println!()
            }
        }

        let sec = secp256k1::SecretKey::from_str(private_key_string);
    }
    //     - (instancetype)initWithPrivateKey:(NSString *)privateKey onChain:(DSChain *)chain {
//     NSParameterAssert(privateKey);
//     NSParameterAssert(chain);
//
//     if (privateKey.length == 0) return nil;
//     if (!(self = [self init])) return nil;
//
//     // mini private key format
//     if ((privateKey.length == 30 || privateKey.length == 22) && [privateKey characterAtIndex:0] == 'L') {
//     if (![privateKey is_valid_dash_private_key_on_chain:chain]) return nil;
//
//     _seckey = [CFBridgingRelease(CFStringCreateExternalRepresentation(SecureAllocator(), (CFStringRef)privateKey,
//     kCFStringEncodingUTF8, 0)) SHA256];
//     _compressed = NO;
//     return self;
//     }
//
//     NSData *d = privateKey.base58checkToData;
//     uint8_t version;
//     if ([chain isMainnet]) {
//     version = DASH_PRIVKEY;
//     } else {
//     version = DASH_PRIVKEY_TEST;
//     }
//
//     if (!d || d.length == 28) d = privateKey.base58ToData;
//     if (d.length < sizeof(UInt256) || d.length > sizeof(UInt256) + 2) d = privateKey.hexToData;
//
//     if ((d.length == sizeof(UInt256) + 1 || d.length == sizeof(UInt256) + 2) && *(const uint8_t *)d.bytes == version) {
//     _seckey = *(const UInt256 *)((const uint8_t *)d.bytes + 1);
//     _compressed = (d.length == sizeof(UInt256) + 2) ? YES : NO;
//     } else if (d.length == sizeof(UInt256))
//     _seckey = *(const UInt256 *)d.bytes;
//
//     return (secp256k1_ec_seckey_verify(_ctx, _seckey.u8)) ? self : nil;
// }
    pub fn init_with_public_key(public_key: Vec<u8>) -> Option<Self> {
        assert!(public_key);
        if public_key.len() != 33 && public_key.len() != 65 {
            return None;
        }
        let compressed = public_key.len() == 33;
        match secp256k1::PublicKey::from_slice(&public_key) {
            Ok(_pk) => Some(ECDSAKey::with_pubkey_compressed(public_key, compressed)),
            Err(err) => {
                println!("init_with_compact_sig: RecoverableSignature::recover: error: {}", err);
                return None;
            }
        }
    }

    fn with_pubkey_compressed(pubkey: Vec<u8>, compressed: bool) -> ECDSAKey {
        ECDSAKey {
            base: Key {},
            compressed,
            pubkey,
            ..Default::default()
        }
    }

    fn recover_ecdsa(digest: &[u8], signature: &RecoverableSignature) -> Result<secp256k1::PublicKey, secp256k1::Error> {
        Secp256k1::new().recover_ecdsa(&Message::from(&message_digest.0), &signature)
    }



}
