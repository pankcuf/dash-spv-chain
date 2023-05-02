use crate::chain::params::ScriptMap;
use crate::util::base58;

fn is_valid_dash_private_key_on_chain(key: &str, script_address: &ScriptMap) -> bool {
    match base58::from_check(key) {
        // wallet import format: https://en.bitcoin.it/wiki/Wallet_import_format
        Ok(data) if data.len() == 33 || data.len() == 34 => data[0] == script_address.privkey,
        // hex encoded key
        Ok(data) => base58::encode_slice(&data).len() == 32,
        Err(..) => false
    }
}

#[inline]
pub fn ceil_log2(mut x: i32) -> i32 {
    let mut r = if x & (x - 1) != 0 { 1 } else { 0 };
    loop {
        x >>= 1;
        if x == 0 {
            break;
        }
        r += 1;
    }
    r
}
