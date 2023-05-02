use hashes::{Hash, sha256d};
use crate::blockdata::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_RETURN, OP_SHAPESHIFT, OP_SHAPESHIFT_SCRIPT};
use crate::chain::params::{BITCOIN_SCRIPT_ADDRESS, ScriptMap};
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::util::base58;
use crate::util::script::{op_len, ScriptElement};

pub trait DataAppend: std::io::Write {
    fn from_coinbase_message(message: &String, height: u32) -> Self;
    fn devnet_genesis_coinbase_message(identifier: &String, version: u16, protocol_version: u32) -> Self;
    fn script_pub_key_for_address(address: &String, script: &ScriptMap) -> Self;
    fn credit_burn_script_pub_key_for_address(address: &String, script_map: &ScriptMap) -> Self;
    fn proposal_info(proposal_info: Vec<u8>) -> Self;
    fn shapeshift_memo_for_address(address: String) -> Self;

    fn append_coinbase_message(&mut self, message: &String, height: u32);
    fn append_devnet_genesis_coinbase_message(&mut self, identifier: &String, version: u16, protocol_version: u32);
    fn append_counted_data(&mut self, data: Vec<u8>) -> usize;
    fn append_credit_burn_script_pub_key_for_address(&mut self, address: &String, script: &ScriptMap);
    fn append_proposal_info(&mut self, proposal_info: &Vec<u8>);
    fn append_script_pub_key_for_address(&mut self, address: &String, script: &ScriptMap);
    fn append_script_push_data(&mut self, data: &Vec<u8>) -> usize;
    fn append_script_push_data_slice(&mut self, data: &[u8]) -> usize;
    fn append_shapeshift_memo_for_address(&mut self, address: String) -> usize;
    fn append_string(&mut self, data: String) -> usize;

    fn script_elements(&self) -> Vec<ScriptElement>;
}


const U16MAX: u32 = u16::MAX as u32;
const U16MAX_PLUS_1: u32 = U16MAX + 1;

impl DataAppend for Vec<u8> /* io::Write */ {

    fn from_coinbase_message(message: &String, height: u32) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_coinbase_message(message, height);
        writer
    }
    fn devnet_genesis_coinbase_message(identifier: &String, version: u16, protocol_version: u32) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_devnet_genesis_coinbase_message(identifier, version, protocol_version);
        writer
    }
    fn script_pub_key_for_address(address: &String, script: &ScriptMap) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_script_pub_key_for_address(address, script);
        writer
    }

    fn credit_burn_script_pub_key_for_address(address: &String, script: &ScriptMap) -> Self {
        let mut writer = Vec::<u8>::new();
        writer.append_credit_burn_script_pub_key_for_address(address, script);
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
        // todo: check
        //NSUInteger l = [message lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        let l = message.len();
        match height {
            0..=0xfc => {
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

    fn append_devnet_genesis_coinbase_message(&mut self, identifier: &String, version: u16, protocol_version: u32) {
        // A little weirder
        // uint8_t l = (uint8_t)[devnetIdentifier lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        // todo: check
        0x51u8.enc(self);
        (identifier.len() as u8).enc(self);
        identifier.enc(self);
    }


    fn append_counted_data(&mut self, data: Vec<u8>) -> usize {
        VarInt(data.len() as u64).enc(self);
        data.enc(self);
        self.len()
    }

    fn append_credit_burn_script_pub_key_for_address(&mut self, address: &String, script: &ScriptMap) {
        // todo: check impl base58checkToData
        match base58::from_check(address.as_str()) {
            Ok(d) if d.len() == 21 => {
                OP_RETURN.into_u8().enc(self);
                self.append_script_push_data_slice(&d[1..]);
            },
            _ => panic!("append_credit_burn_script_pub_key_for_address: base58::from_check error")
        }
    }

    fn append_proposal_info(&mut self, proposal_info: &Vec<u8>) {
        let hash = sha256d::Hash::hash(proposal_info).into_inner();
        OP_RETURN.into_u8().enc(self);
        self.append_script_push_data_slice(&hash);
    }

    fn append_script_pub_key_for_address(&mut self, address: &String, script: &ScriptMap) {
        let ScriptMap { pubkey, script, ..} = script;
        match base58::from_check(address.as_str()) {
            Ok(data) => match &data[..] {
                [v @ pubkey, data @ ..] => {
                    OP_DUP.into_u8().enc(self);
                    OP_HASH160.into_u8().enc(self);
                    self.append_script_push_data_slice(data);
                    OP_EQUALVERIFY.into_u8().enc(self);
                    OP_CHECKSIG.into_u8().enc(self);
                },
                [v @ script, data @ ..] => {
                    OP_HASH160.into_u8().enc(self);
                    self.append_script_push_data_slice(data);
                    OP_EQUAL.into_u8().enc(self);
                },
                _ => {}
            },
            _ => panic!("append_script_pub_key_for_address: base58::from_check error")
        }

        // match base58::from_check(address.as_str()) {
        //     Ok(d) if d.len() == 21 => {
        //         let version = d[0];
        //         if version == script.pubkey {
        //             OP_DUP.into_u8().enc(self);
        //             OP_HASH160.into_u8().enc(self);
        //             self.append_script_push_data_slice(&d[1..]);
        //             OP_EQUALVERIFY.into_u8().enc(self);
        //             OP_CHECKSIG.into_u8().enc(self);
        //         } else if version == script.script {
        //             OP_HASH160.into_u8().enc(self);
        //             self.append_script_push_data_slice(&d[1..]);
        //             OP_EQUAL.into_u8().enc(self);
        //         }
        //     },
        //     _ => panic!("append_script_pub_key_for_address: base58::from_check error")
        // }
    }
    fn append_script_push_data_slice(&mut self, data: &[u8]) -> usize {
        let len = data.len();
        match len {
            0 => { return 0; },
            1..=0x4b => {
                (len as u8).enc(self);
            }
            0x4c..=0xffff => {
                OP_PUSHDATA1.into_u8().enc(self);
                (len as u8).enc(self);
            },
            0x10000..=0xffffffff => {
                OP_PUSHDATA2.into_u8().enc(self);
                (len as u16).enc(self);
            },
            _ => {
                OP_PUSHDATA4.into_u8().enc(self);
                (len as u32).enc(self);
            },
        }
        data.to_vec().enc(self);
        self.len()
    }

    fn append_script_push_data(&mut self, data: &Vec<u8>) -> usize {
        // todo: migrate into slice
        let len = data.len();
        match len {
            0 => { return 0; },
            1..=0x4b => {
                (len as u8).enc(self);
            }
            0x4c..=0xffff => {
                OP_PUSHDATA1.into_u8().enc(self);
                (len as u8).enc(self);
            },
            0x10000..=0xffffffff => {
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
                script_push.extend(d.clone().drain(1..d.len()));
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

    fn script_elements(&self) -> Vec<ScriptElement> {
        let mut a = Vec::<ScriptElement>::new();
        let len = self.len();
        let mut chunk_size = 0usize;
        let mut i = 0usize;
        'outer: while i < len {
            match self[i] {
                x @ 0 | x @ 0x4f..=0xff => {
                    chunk_size = 1;
                    a.push(ScriptElement::Number(x));
                    i += chunk_size;
                    continue 'outer;
                },
                0x4c => { // OP_PUSHDATA1
                    i += 1;
                    if i + std::mem::size_of::<u8>() > len {
                        break 'outer;
                    }
                    chunk_size = self[i] as usize;
                    i += std::mem::size_of::<u8>();
                },
                0x4d => { // OP_PUSHDATA2
                    i += 1;
                    if i + std::mem::size_of::<u16>() > len {
                        break 'outer;
                    }
                    chunk_size = (self[i] as u16).swap_bytes() as usize;
                    i += std::mem::size_of::<u16>();
                },
                0x4e => { // OP_PUSHDATA4
                    i += 1;
                    if i + std::mem::size_of::<u32>() > len {
                        break 'outer;
                    }
                    chunk_size = (self[i] as u32).swap_bytes() as usize;
                    i += std::mem::size_of::<u32>();
                },
                _ => {
                    chunk_size = self[i] as usize;
                    i += 1;
                }
            };
            if i + chunk_size > len {
                return a;
            }
            let chunk = &self[i..i+chunk_size];
            a.push(ScriptElement::Data(chunk, op_len(chunk)));
            i += chunk_size;
        }
        a
    }
}

