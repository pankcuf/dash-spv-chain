use bls_signatures::bip32::{BIP32_EXTENDED_PUBLIC_KEY_SIZE, ChainCode, ExtendedPrivateKey, ExtendedPublicKey};
use bls_signatures::{BasicSchemeMPL, BlsError, G1Element, LegacySchemeMPL, PrivateKey, Scheme};
use crate::crypto::byte_util::{AsBytes, AsBytesVec, BytesDecodable, Zeroable};
use crate::crypto::{UInt256, UInt384, UInt768};
use crate::crypto::primitives::data;
use crate::crypto::primitives::data::random_initialization_vector_of_size;
use crate::derivation::derivation_path::IDerivationPath;
use crate::derivation::uint256_index_path::{IIndexPath, IndexPath};
use crate::keys::key::{IKey, Key};
use crate::keys::KeyType;
use crate::platform::base::serializable_object::SerializableValue;

pub struct BLSKey {
    pub base: Key,
    pub extended_private_key_data: Vec<u8>,
    pub extended_public_key_data: Vec<u8>,
    pub chain_code: ChainCode,
    pub secret_key: UInt256,
    pub public_key: UInt384,
    pub use_legacy: bool,
    engine: dyn Scheme,
}

impl BLSKey {

    fn bls_private_key(&self) -> PrivateKey {
        if !self.secret_key.is_zero() {
            PrivateKey::from_bytes(self.secret_key.as_bytes(), true)
        } else if !self.extended_private_key_data.is_empty() {
            ExtendedPrivateKey::from_bytes(self.extended_private_key_data.as_bytes())
        } else {
            PrivateKey::from_bytes(self.secret_key.as_bytes(), true)
        }.unwrap()
    }

    fn bls_public_key(&self) -> G1Element {
        if self.public_key.is_zero() {
            self.bls_private_key().g1_element()
        } else if self.use_legacy {
            G1Element::from_bytes_legacy(self.public_key.as_bytes())
        } else {
            G1Element::from_bytes(self.public_key.as_bytes())
        }.unwrap()
    }


    pub(crate) fn key_with_private_key(data: &Vec<u8>, use_legacy: bool) -> Option<dyn IKey> {
        todo!()
    }

    pub(crate) fn key_with_public_key(key: &UInt384, use_legacy: bool) -> BLSKey {
        todo!()
    }

    pub fn encrypt_using_initialization_vector<K: IKey>(&self, initialization_vector: Vec<u8>, data: &Vec<u8>, public_key: &K) -> Vec<u8> {

        //bls::G1Element pk = secretKey.blsPrivateKey * peerPubKey.blsPublicKey;
        let bls_pk = self.bls_private_key() * public_key.bls_public_key();
        // self.bls_private_key().
        todo!("impl AES")

        // std::vector<uint8_t> symKey = pk.Serialize(true);
        // symKey.resize(32);
        //
        // NSData *resultData = AES256EncryptDecrypt(kCCEncrypt, self, (uint8_t *)symKey.data(), ivData.bytes);
        //
        // NSMutableData *finalData = [ivData mutableCopy];
        // [finalData appendData:resultData];
        // return finalData;

    }
}

impl SerializableValue for BLSKey {
    fn as_data(&self) -> &[u8] {
        todo!()
    }
}

impl IKey for BLSKey {
    fn r#type(&self) -> &KeyType {
        &KeyType::BLS // &KeyType::BLSBasic
    }

    fn encrypt<K: IKey>(&self, data: &Vec<u8>, public_key: &K) -> Vec<u8> {
        self.encrypt_using_initialization_vector(
            random_initialization_vector_of_size(16 /*AES_BLOCKSIZE*/),
            data,
            public_key)
    }

    fn sign(&self, data: &Vec<u8>) -> Vec<u8> {
        self.sign_digest(UInt256::from_bytes(data).unwrap()).as_bytes().to_vec()
    }

    fn verify(&self, message_digest: &Vec<u8>, signature: &Vec<u8>) -> bool {
        todo!()
    }

    fn private_derive_to_path<T>(&self, index_path: IndexPath<T>) -> Option<dyn IKey> {
        if let Ok(bls_extended_private_key) = ExtendedPrivateKey::from_bytes(self.extended_private_key_data.as_bytes()) {
            let derived_extended_private_key = BLSKey::derive(bls_extended_private_key, index_path);
            return Some(BLSKey::init_with_bls_extended_private_key(&derived_extended_private_key, self.use_legacy));
        }
        None
    }

    fn private_key_data(&self) -> Option<Vec<u8>> {
        if self.secret_key.is_zero() {
            None
        } else {
            Some(self.secret_key.as_bytes_vec().clone())
        }
    }
    fn public_key_data(&self) -> &Vec<u8> {
        &self.public_key.as_bytes_vec()
    }

    fn private_derive_to256bit_derivation_path(&self, derivation_path: &dyn IDerivationPath) -> Option<Self> {
        self.private_derive_to_path(derivation_path.base_index_path())
    }

    fn hmac_256_data(&self, data: &Vec<u8>) -> UInt256 {
        todo!()
    }
}

impl BLSKey {

    /// A little recursive magic since extended private keys can't be re-assigned in the library
    pub fn derive(extended_private_key: ExtendedPrivateKey, index_path: IndexPath<u32>) -> ExtendedPrivateKey {
        if index_path.length() == 0 {
            return extended_private_key;
        }
        let top_index_path = *index_path.indexes.first().unwrap();
        let sk_child = extended_private_key.private_child(top_index_path);
        //let sk_child = extended_private_key.private_child_legacy(top_index_path);
        let index_path = IndexPath::index_path_with_indexes(index_path.indexes[1..].to_owned());
        Self::derive(sk_child, index_path)
    }

    pub fn init_with_bls_extended_public_key(bls_extended_public_key: ExtendedPublicKey, use_legacy: bool) ->  Self {
        let (extended_public_key_data, engine) = if use_legacy {
            (bls_extended_public_key.serialize_legacy(), LegacySchemeMPL::new() )
        } else {
            (bls_extended_public_key.serialize(), BasicSchemeMPL::new())
        };
        // TODO: impl SecureAllocator
        // NSMutableData *blsExtendedPublicKeyData = [NSMutableData secureDataWithCapacity:bls::ExtendedPublicKey::SIZE];
        // [blsExtendedPublicKeyData appendBytes:blsExtendedPublicKeyBytes length:bls::ExtendedPublicKey::SIZE];
        let bls_public_key = bls_extended_public_key.public_key();
        let public_key_data = if use_legacy {
            bls_public_key.serialize_legacy()
        } else {
            bls_public_key.serialize()
        };
        Self {
            base: Key {},
            extended_private_key_data: vec![],
            extended_public_key_data: extended_public_key_data.to_vec(),
            chain_code: public_key.chain_code(),
            secret_key: UInt256::MIN,
            public_key: UInt384(*public_key_data),
            engine,
            use_legacy
        }
    }

    pub fn init_with_bls_extended_private_key<T>(bls_extended_private_key: &ExtendedPrivateKey, use_legacy: bool) -> Option<Self> {
        let extended_private_key_data = bls_extended_private_key.serialize();
        let extended_public_key_opt = if use_legacy {
            bls_extended_private_key.extended_public_key()
        } else {
            bls_extended_private_key.extended_public_key_legacy()
        };
        if extended_public_key_opt.is_err() {
            println!("Can't restore extended_public_key");
            return None;
        }
        let extended_public_key = extended_public_key_opt.unwrap();
        let extended_public_key_data = extended_public_key.serialize();
        let chain_code = bls_extended_private_key.chain_code();
        let bls_private_key = bls_extended_private_key.private_key();
        let bls_public_key_opt = bls_private_key.g1_element();
        if bls_public_key_opt.is_err() {
            println!("Can't restore bls_public_key");
            return None;
        }
        let bls_public_key = bls_public_key_opt.unwrap();
        let bls_public_key_bytes = if use_legacy {
            bls_public_key.serialize_legacy()
        } else {
            bls_public_key.serialize()
        };
        let secret_key_opt = UInt256::from_bytes(bls_private_key.serialize().as_bytes());
        if secret_key_opt.is_none() {
            println!("Can't restore secret_key");
            return None;
        }
        Some(Self {
            base: Key {},
            extended_private_key_data: extended_private_key_data.to_vec(),
            extended_public_key_data: extended_public_key_data.to_vec(),
            chain_code,
            secret_key: secret_key_opt.unwrap(),
            public_key: UInt384(*bls_public_key_bytes),
            use_legacy,
            engine: if use_legacy { LegacySchemeMPL::new() } else { BasicSchemeMPL::new() }
        })
    }




    pub fn public_key_from_extended_public_key_data<T>(data: &Vec<u8>, index_path: &IndexPath<T>, use_legacy: bool) -> Option<Vec<u8>> {
        // let extended_public_key = BLSKey::ke
        BLSKey::key_w
        let extended_public_key = if use_legacy {
            ExtendedPublicKey::from_bytes_legacy()
        } else {

        }
        bls_signatures::ExtendedPublicKey

    }


    + (NSData *_Nullable)publicKeyFromExtendedPublicKeyData:(NSData *)publicKeyData atIndexPath:(NSIndexPath *)indexPath useLegacy:(BOOL)useLegacy {
    DSBLSKey *extendedPublicKey = [DSBLSKey keyWithExtendedPublicKeyData:publicKeyData useLegacy:useLegacy];
    DSBLSKey *extendedPublicKeyAtIndexPath = [extendedPublicKey publicDeriveToPath:indexPath];
    NSData *data = [NSData dataWithUInt384:extendedPublicKeyAtIndexPath.publicKey];
    NSAssert(data, @"Public key should be created");
    return data;
}


pub fn sign_digest(&self, md: UInt256) -> UInt768 {
        todo!()
        // if (uint256_is_zero(self.secretKey) && !self.extendedPrivateKeyData.length) return UINT768_ZERO;
        // bls::PrivateKey blsPrivateKey = [self blsPrivateKey];
        // bls::G2Element blsSignature = bls::LegacySchemeMPL().Sign(blsPrivateKey, bls::Bytes(md.u8, sizeof(UInt256)));
        // UInt768 signature = [NSData dataWithBytes:blsSignature.Serialize(self.useLegacy).data() length:sizeof(UInt768)].UInt768;
        // return signature;

    }
}
