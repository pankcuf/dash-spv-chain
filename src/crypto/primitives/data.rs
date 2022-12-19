
pub const BIP32_SEED_KEY: &str = "Bitcoin seed";

pub const BIP32_XPRV_TESTNET: &str = "\x04\x35\x83\x94";
pub const BIP32_XPUB_TESTNET: &str = "\x04\x35\x87\xCF";

pub const BIP32_XPRV_MAINNET: &str = "\x04\x88\xAD\xE4";
pub const BIP32_XPUB_MAINNET: &str = "\x04\x88\xB2\x1E";

pub const DIP14_DPTS_TESTNET: &str = "\x0E\xED\x27\x74";
pub const DIP14_DPTP_TESTNET: &str = "\x0E\xED\x27\x0B";

pub const DIP14_DPMS_MAINNET: &str = "\x0E\xEC\xF0\x2E";
pub const DIP14_DPMP_MAINNET: &str = "\x0E\xEC\xEF\xC5";


#[inline]
pub fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
    use secp256k1::rand;
    use secp256k1::rand::distributions::Uniform;
    use secp256k1::rand::Rng;
    let mut rng = rand::thread_rng();
    let range = Uniform::new(0, 255);
    (0..size).map(|_| rng.sample(&range)).collect()
}

