use std::io;
use hashes::{Hash, sha256d};
use crate::blockdata::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_RETURN, OP_SHAPESHIFT, OP_SHAPESHIFT_SCRIPT};
use crate::blockdata::opcodes::Ordinary::{OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
use crate::chain::chain::Chain;
use crate::chain::params::{BITCOIN_PUBKEY_ADDRESS, BITCOIN_SCRIPT_ADDRESS, DASH_PUBKEY_ADDRESS, DASH_PUBKEY_ADDRESS_TEST, DASH_SCRIPT_ADDRESS, DASH_SCRIPT_ADDRESS_TEST};
use crate::consensus::{Encodable, WriteExt};
use crate::crypto::{UInt160, UInt256};
use crate::util::base58;

pub fn x11_hash(data: &[u8]) -> UInt256 {
    todo!("Implement x11 hashing")
}

pub fn address_from_hash160_for_chain(hash: &UInt160, chain: &Chain) -> Option<String> {
    let mut writer: Vec<u8> = Vec::new();
    let v = if chain.is_mainnet() { DASH_PUBKEY_ADDRESS } else { DASH_PUBKEY_ADDRESS_TEST };
    v.enc(&mut writer);
    hash.enc(&mut writer);
    let val = u32::from_le_bytes(sha256d::Hash::hash(&buffer).into_inner()[0..4] as [u8; 4]);
    val.enc(&mut writer);
    Some(base58::encode_slice(&writer))
}

pub fn address_with_public_key_data(data: &Vec<u8>, chain: &Chain) -> Option<String> {
    NSParameterAssert(data);
    NSParameterAssert(chain);

    NSMutableData *d = [NSMutableData secureDataWithCapacity:160 / 8 + 1];
    uint8_t version;
    UInt160 hash160 = data.hash160;

    if ([chain isMainnet]) {
    version = DASH_PUBKEY_ADDRESS;
    } else {
    version = DASH_PUBKEY_ADDRESS_TEST;
    }

    [d appendBytes:&version
    length:1];
    [d appendBytes:&hash160 length:sizeof(hash160)];
    return [NSString base58checkWithData:d];
}


pub fn is_valid_dash_address_on_chain(address: &String, chain: &Chain) -> bool {
    if address.len() > 35 {
        return false;
    }
    match base58::from_check(address.as_str()) {
        Ok(data) => {
            if data.len() != 21 {
                return false;
            }
            let version = data[0];
            if chain.is_mainnet() {
                version == DASH_PUBKEY_ADDRESS || version == DASH_SCRIPT_ADDRESS
            } else {
                version == DASH_PUBKEY_ADDRESS_TEST || version == DASH_SCRIPT_ADDRESS_TEST
            }
        },
        Err(err) => { return false; }
    }
}


// NOTE: It's important here to be permissive with scriptSig (spends) and strict with scriptPubKey (receives). If we
// miss a receive transaction, only that transaction's funds are missed, however if we accept a receive transaction that
// we are unable to correctly sign later, then the entire wallet balance after that point would become stuck with the
// current coin selection code
pub fn address_with_script_pub_key(script: &Vec<u8>, chain: &Chain) -> Option<String> {
    if (script == (id)[NSNull null]) return nil;

    NSArray *elem = [script scriptElements];
    NSUInteger l = elem.count;
    NSMutableData *d = [NSMutableData data];
    uint8_t v;

    if ([chain isMainnet]) {
    v = DASH_PUBKEY_ADDRESS;
    } else {
    v = DASH_PUBKEY_ADDRESS_TEST;
    }

    if (l == 5 && [elem[0] intValue] == OP_DUP && [elem[1] intValue] == OP_HASH160 && [elem[2] intValue] == 20 &&
        [elem[3] intValue] == OP_EQUALVERIFY && [elem[4] intValue] == OP_CHECKSIG) {
// pay-to-pubkey-hash scriptPubKey
        [d appendBytes:&v length:1];
        [d appendData:elem[2]];
    } else if (l == 3 && [elem[0] intValue] == OP_HASH160 && [elem[1] intValue] == 20 && [elem[2] intValue] == OP_EQUAL) {
// pay-to-script-hash scriptPubKey
        if ([chain isMainnet]) {
        v = DASH_SCRIPT_ADDRESS;
        } else {
        v = DASH_SCRIPT_ADDRESS_TEST;
        }
        [d appendBytes:&v
        length:1];
        [d appendData:elem[1]];
    } else if (l == 2 && ([elem[0] intValue] == 65 || [elem[0] intValue] == 33) && [elem[1] intValue] == OP_CHECKSIG) {
// pay-to-pubkey scriptPubKey
        [d appendBytes:&v length:1];
        [d appendBytes:[elem[0] hash160].u8 length:sizeof(UInt160)];
    } else
    return nil; // unknown script type

    return [self base58checkWithData:d];
}

pub(crate) fn address_with_script_sig(signature: &Option<Vec<u8>>, chain: &Chain) -> Option<String> {
    todo!()
}


fn is_valid_dash_private_key_on_chain(string: &str, chain: &Chain) -> bool {
    return match base58::from_check(string) {
        Ok(data) => {
            if data.len() == 33 || data.len() == 34 {
                // wallet import format: https://en.bitcoin.it/wiki/Wallet_import_format
                if chain.params.chain_type.is_mainnet() {
                    data[0] == DASH_PRIVKEY
                } else {
                    data[0] == DASH_PRIVKEY_TEST
                }
            } else {
                // hex encoded key
                base58::encode_slice(&data).len() == 32
            }
        },
        Err(err) => {
            println!("is_valid_dash_private_key_on_chain: error: {}", err);
            false
        }
    }
}

pub fn shapeshift_outbound_address_force_script(script: &Option<Vec<u8>>) -> Option<String> {
    if let Some(script) = script {
        if script[0] == OP_RETURN.into_u8() {
            if script[2] == OP_SHAPESHIFT.into_u8() {
                let mut data: Vec<u8> = vec![BITCOIN_SCRIPT_ADDRESS] + script[3..script[1] - 1];
                // data.extend(script[3..script[1] - 1]);
                return Some(base58::check_encode_slice(&data));
            }
        }
    }
    None
}

pub fn shapeshift_outbound_address_for_script(script: &Option<Vec<u8>>, chain: &Chain) -> Option<String> {
    if chain.is_mainnet() {
        if let Some(script) = script {
            if script[0] != OP_RETURN.into_u8() {
                return None;
            } else if script[2] == OP_SHAPESHIFT.into_u8() {
                let mut data = Vec::<u8>::new();
                BITCOIN_PUBKEY_ADDRESS.enc(&mut data);
                data.extend(script[3..script[1] - 1]);
                return Some(base58::check_encode_slice(&data));
            } else if script[2] == OP_SHAPESHIFT_SCRIPT.into_u8() {
                let mut data = Vec::<u8>::new();
                BITCOIN_SCRIPT_ADDRESS.enc(&mut data);
                data.extend(script[3..script[1] - 1]);
                return Some(base58::check_encode_slice(&data));
            }
        }
    }
    None
}

