use std::collections::HashSet;
use std::fmt::Write;
use byte::{BytesExt, TryRead};
use hashes::{Hash, sha256d};
use secp256k1::rand;
use secp256k1::rand::distributions::Uniform;
use secp256k1::rand::Rng;
use crate::blockdata::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_RETURN, OP_SHAPESHIFT, OP_SHAPESHIFT_SCRIPT};
use crate::chain::chain::Chain;
use crate::chain::params::{BITCOIN_SCRIPT_ADDRESS, DASH_PUBKEY_ADDRESS, DASH_PUBKEY_ADDRESS_TEST, DASH_SCRIPT_ADDRESS, DASH_SCRIPT_ADDRESS_TEST};
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::util::base58;

pub const VAR_INT16_HEADER: u8 = 0xfd;
pub const VAR_INT32_HEADER: u8 = 0xfe;
pub const VAR_INT64_HEADER: u8 = 0xff;
pub const DASH_MESSAGE_MAGIC: &str = "DarkCoin Signed Message:\n";

pub trait Data {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
    fn true_bits_count(&self) -> u64;
    fn script_elements(&self) -> Vec<ScriptElement> { vec![] }
    //fn random_initialization_vector_of_size(size: usize) -> Vec<u8>;
}

pub enum ScriptElement {
    Number(i32),
    Data(Vec<u8>)
}

impl ScriptElement {
    pub fn length(&self) -> usize {
        match self {
            ScriptElement::Number(_) => 1,
            ScriptElement::Data(value) => value.len()
        }
    }

    pub fn data(&self) -> Vec<u8> {
        match self {
            ScriptElement::Number(value) => value.to_be_bytes().to_vec(),
            ScriptElement::Data(value) => value.clone()
        }
    }
}

impl Data for [u8] {

    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        let offset = &mut ((index / 8) as usize);
        let bit_position = index % 8;
        match self.read_with::<u8>(offset, byte::LE) {
            Ok(bits) => (bits >> bit_position) & 1 != 0,
            _ => false
        }
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        for mut i in 0..self.len() {
            let mut bits: u8 = self.read_with(&mut i, byte::LE).unwrap();
            for _j in 0..8 {
                if bits & 1 != 0 {
                    count += 1;
                }
                bits >>= 1;
            }
        }
        count
    }

    // fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
    //     todo!()
    // }

    // fn script_elements(&self) -> Vec<ScriptElement> {
    //     todo!();
    //     vec![]
        // let mut a = Vec::new();
        // let mut l = 0;
        // let length = self.len();
        // for mut i in (0..length).step_by(l) {
        //     if self[i] > OP_PUSHDATA4.into_u8() {
        //         l = 1;
        //         a.push(ScriptElement::Number(self[i]));
        //         continue;
        //     }
        //
        //     match b[i] {
        //         OP_PUSHBYTES_0 => {
        //             l = 1;
        //             a.push(ScriptElement::Number(0));
        //             continue;
        //         },
        //         OP_PUSHDATA1 => {
        //             i += 1;
        //             if i + std::mem::size_of::<u8>() > length {
        //                 return a;
        //             }
        //             l = b[i];
        //             i += std::mem::size_of::<u8>();
        //             break;
        //         },
        //         OP_PUSHDATA2 => {
        //             i += 1;
        //             if i + std::mem::size_of::<u16>() > length {
        //                 return a;
        //             }
        //             let bbb = self[i];
        //             l = u16::from_le_bytes(self[i..]);
        //             //l = CFSwapInt16LittleToHost(*(uint16_t *)&b[i]);
        //             i += std::mem::size_of::<u16>();
        //             break;
        //         },
        //         OP_PUSHDATA4 => {
        //             i += 1;
        //             if i + std::mem::size_of::<u32>() > length {
        //                 return a;
        //             }
        //             l - u32::from_le_bytes(self[i..]);
        //             //l = CFSwapInt32LittleToHost(*(uint32_t *)&b[i]);
        //             i += std::mem::size_of::<u32>();
        //             break;
        //
        //         }
        //         _ => {
        //             l = self[i];
        //             i += 1;
        //             break
        //         }
        //     }
        //     if i + l > length {
        //         return a;
        //     }
        //     a.push(ScriptElement::Data(self[i..i+l]));
        //     //[a addObject:[NSData dataWithBytes:&b[i] length:l]];
        // }
        // a
    // }
}


pub fn hex_with_data(data: &[u8]) -> String {
    let n = data.len();
    let mut s = String::with_capacity(2 * n);
    let iter = data.iter();
    for a in iter {
        write!(s, "{:02x}", a).unwrap();
    }
    s
}


pub fn short_hex_string_from(data: &[u8]) -> String {
    let hex_data = hex_with_data(data);
    if hex_data.len() > 7 {
        hex_data[..7].to_string()
    } else {
        hex_data
    }
}


/// Extracts the common values in `a` and `b` into a new set.
pub fn inplace_intersection<T>(a: &mut HashSet<T>, b: &mut HashSet<T>) -> HashSet<T>
    where
        T: std::hash::Hash,
        T: Eq,
{
    let x: HashSet<(T, bool)> = a
        .drain()
        .map(|v| {
            let intersects = b.contains(&v);
            (v, intersects)
        })
        .collect();
    let mut c = HashSet::new();
    for (v, is_inter) in x {
        if is_inter {
            c.insert(v);
        } else {
            a.insert(v);
        }
    }
    b.retain(|v| !c.contains(v));
    c
}

pub trait DataAppend: std::io::Write {
    fn from_coinbase_message(message: &String, height: u32) -> Self;
    fn script_pub_key_for_address(address: &String, chain: &Chain) -> Self;
    fn credit_burn_script_pub_key_for_address(address: &String, chain: &Chain) -> Self;
    fn proposal_info(proposal_info: Vec<u8>) -> Self;
    fn shapeshift_memo_for_address(address: String) -> Self;

    fn append_coinbase_message(&mut self, message: &String, height: u32) -> Self;
    fn append_counted_data(&mut self, data: Vec<u8>) -> usize;
    fn append_credit_burn_script_pub_key_for_address(&mut self, address: &String, chain: &Chain);
    fn append_proposal_info(&mut self, proposal_info: &Vec<u8>);
    fn append_script_pub_key_for_address(&mut self, address: &String, chain: &Chain);
    fn append_script_push_data(&mut self, data: &Vec<u8>) -> usize;
    fn append_shapeshift_memo_for_address(&mut self, address: String) -> usize;
    fn append_string(&mut self, data: String) -> usize;
}
const U16MAX: u32 = u16::MAX as u32;
const U16MAX_PLUS_1: u32 = U16MAX + 1;

impl DataAppend for Vec<u8> /* io::Write */ {

    fn from_coinbase_message(message: &String, height: u32) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_coinbase_message(message, height);
        writer
    }
    fn script_pub_key_for_address(address: &String, chain: &Chain) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_script_pub_key_for_address(address, chain);
        writer
    }

    fn credit_burn_script_pub_key_for_address(address: &String, chain: &Chain) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_credit_burn_script_pub_key_for_address(address, chain);
        writer
    }

    fn proposal_info(proposal_info: Vec<u8>) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_proposal_info(&proposal_info);
        writer
    }

    fn shapeshift_memo_for_address(address: String) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_shapeshift_memo_for_address(address);
        writer
    }

    fn append_coinbase_message(&mut self, message: &String, height: u32) {
        //NSUInteger l = [message lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        let l = message.len();
        match height {
            0..0xfd => {
                let header = l as u8;
                let payload = height as u8;
                header.enc(self);
                payload.enc(self);
            },
            0xfd..=U16MAX => {
                let header = (0xfd + l) as u8;
                let payload = (height as u16).swap_bytes();
                header.enc(self);
                payload.enc(self);
            },
            U16MAX_PLUS_1..=u32::MAX => {
                let header = (0xfe + l) as u8;
                let payload = height.swap_bytes();
                header.enc(self);
                payload.enc(self);
            }
        }
        message.enc(self);
    }

    fn append_counted_data(&mut self, data: Vec<u8>) -> usize {
        VarInt(data.len() as u64).enc(self);
        data.enc(self);
        self.len()
    }

    fn append_credit_burn_script_pub_key_for_address(&mut self, address: &String, chain: &Chain) {
        // todo: check impl base58checkToData
        match base58::from_check(address.as_str()) {
            Ok(d) if d.len() == 21 => {
                OP_RETURN.into_u8().enc(self);
                // todo: check array upper bound len or len - 1
                let hash = d[1..d.len() - 1];
                self.append_script_push_data(&hash.to_vec());
            },
            _ => panic!("append_credit_burn_script_pub_key_for_address: base58::from_check error")
        }
    }

    fn append_proposal_info(&mut self, proposal_info: &Vec<u8>) {
        let hash = sha256d::Hash::hash(proposal_info).into_inner();
        OP_RETURN.into_u8().enc(self);
        self.append_script_push_data(&hash.to_vec());
    }

    fn append_script_pub_key_for_address(&mut self, address: &String, chain: &Chain) {
        // todo: check impl base58checkToData
        match base58::from_check(address.as_str()) {
            Ok(d) if d.len() == 21 => {
                let version = d[0];
                // todo: check array upper bound len or len - 1
                let hash = d[1..d.len() - 1];
                let (pubkey_address, script_address) = if chain.is_mainnet() {
                    (DASH_PUBKEY_ADDRESS, DASH_SCRIPT_ADDRESS)
                } else {
                    (DASH_PUBKEY_ADDRESS_TEST, DASH_SCRIPT_ADDRESS_TEST)
                };
                if version == pubkey_address {
                    OP_DUP.into_u8().enc(self);
                    OP_HASH160.into_u8().enc(self);
                    self.append_script_push_data(&hash.to_vec());
                    OP_EQUALVERIFY.into_u8().enc(self);
                    OP_CHECKSIG.into_u8().enc(self);
                } else if version == script_address {
                    OP_HASH160.into_u8().enc(self);
                    self.append_script_push_data(&hash.to_vec());
                    OP_EQUAL.into_u8().enc(self);
                }
            },
            _ => panic!("append_script_pub_key_for_address: base58::from_check error")
        }
    }

    fn append_script_push_data(&mut self, data: &Vec<u8>) -> usize {
        // todo: migrate into slice
        let len = data.len();
        let pushdata1_usize = PUSHDATA1 as usize;
        match len {
            0 => { return 0; },
            1..pushdata1_usize => {
                (len as u8).enc(self);
            }
            pushdata1_usize..0x10000 => {
                OP_PUSHDATA1.into_u8().enc(self);
                (len as u8).enc(self);
            },
            0x10000..=0xFFFFFFFF => {
                OP_PUSHDATA2.into_u8().enc(self);
                (len as u16).enc(self);
            },
            _ => {
                OP_PUSHDATA4.into_u8().enc(self);
                (len as u32).enc(self);
            },
        }
        data.enc(self);
        self.len()
    }

    fn append_shapeshift_memo_for_address(&mut self, address: String) -> usize {
        match base58::from_check(address.as_str()) {
            Ok(d) if d.len() == 21 => {
                let mut script_push = Vec::<u8>::new();
                if d[0] == BITCOIN_SCRIPT_ADDRESS {
                    OP_SHAPESHIFT_SCRIPT.into_u8().enc(&mut script_push);
                } else {
                    // shapeshift is actually part of the message
                    OP_SHAPESHIFT.into_u8().enc(&mut script_push);
                }
                script_push.extend(d.clone().drain(1..d.len() - 1));
                OP_RETURN.into_u8().enc(self);
                self.append_script_push_data(&script_push)
            },
            _ => panic!("can't convert from base58 check")
        }
    }

    fn append_string(&mut self, data: String) -> usize {
        // NSUInteger l = [s lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        // [self appendVarInt:l];
        // [self appendBytes:s.UTF8String length:l];
        VarInt(data.len() as u64).enc(self);
        data.enc(self);
        self.len()

    }
}

pub trait TryReadWithChain<'a, Ctx = ()>: TryRead<'a, Ctx> {

}
