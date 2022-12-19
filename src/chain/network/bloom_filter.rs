use std::cmp::min;
use std::f64::consts::{E, LN_2};
use std::intrinsics::{logf64, powf64};
use byte::ctx::Endian;
use byte::{BytesExt, LE, TryRead};
use crate::blockdata::opcodes::all::OP_PUSHDATA4;
use crate::chain::tx::transaction::ITransaction;
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::data_ops::{Data, ScriptElement};
use crate::crypto::VarBytes;
use murmur3::murmur3_32;

pub const BLOOM_MAX_HASH_FUNCS: u32 = 50;

/// one eighth of bitcoinj
pub const BLOOM_DEFAULT_FALSEPOSITIVE_RATE: f64 = 0.0000625;
pub const BLOOM_REDUCED_FALSEPOSITIVE_RATE: f64 = 0.00000625;
pub const BLOOM_UPDATE_NONE: u8 = 0;
pub const BLOOM_UPDATE_ALL: u8 = 1;
pub const BLOOM_UPDATE_P2PUBKEY_ONLY: u8 = 2;
/// this allows for 10,000 elements with a <0.0001% false positive rate
pub const BLOOM_MAX_FILTER_LENGTH: u64 = 36000;

pub struct BloomFilter {
    pub tweak: u32,
    pub flags: u8,
    pub element_count: u64,
    pub false_positive_rate: f64,

    filter: Vec<u8>,
    hash_funcs: u32,
}

impl BloomFilter {

    pub fn init_with_full_match() -> Self {
        Self {
            tweak: 0,
            flags: BLOOM_UPDATE_NONE,
            element_count: 0,
            false_positive_rate: 0.0,
            filter: vec![b'\xFF'],
            hash_funcs: 0
        }
    }

    pub fn init_with_false_positive_rate(false_positive_rate: f64, element_count: u64, tweak: u32, flags: u8) -> Self {
        let length = min(if false_positive_rate < f64::EPSILON {
            BLOOM_MAX_FILTER_LENGTH
        } else {
            (-1.0 / (LN_2 * LN_2)) * element_count * f64::ln(false_positive_rate) / 8.0
        }, BLOOM_MAX_FILTER_LENGTH);
        let filter = if length < 1 { vec![1] } else { length.to_le_bytes().to_vec() };
        let hash_funcs = min((filter.len() * 8.0 / element_count) * LN_2, BLOOM_MAX_HASH_FUNCS);
        Self {
            tweak,
            flags,
            element_count,
            false_positive_rate,
            filter,
            hash_funcs
        }
    }

    pub fn hash(&self, data: &mut Vec<u8>, hash_num: u32) -> u32 {
        murmur3_32(data, hash_num * 0xfba4c795 + self.tweak) % (self.filter.len() * 8)
    }

    pub fn contains_data(&self, data: &mut Vec<u8>) -> bool {
        let b = self.filter.clone();
        for _i in 0..self.hash_funcs {
            let idx = self.hash(data, 1);
            if !(b[idx >> 3] & (1 << (7 & idx))) {
                return false;
            }
        }
        true
    }

    pub fn insert_data(&mut self, &mut data: Vec<u8>) {
        let b = &mut self.filter.clone();
        for _i in 0..self.hash_funcs {
            let idx = self.hash(data, 1);
            b[idx >> 3] |= (1 << (7 & idx));

        }
        self.element_count += 1;
    }

    pub fn update_with_transaction(&mut self, tx: &dyn ITransaction) {
        let mut buffer: Vec<u8> = Vec::new();
        let mut n = 0u32;
        for output in tx.outputs() {
            if let Some(script) = output.script {
                for elem in script.script_elements() {
                    if elem.int_value() > OP_PUSHDATA4 as i32 || elem.int_value() == 0 || !self.contains_data(&mut elem.data()) {
                        continue;
                    }
                    buffer.clear();
                    tx.tx_hash().enc(&mut buffer);
                    n.enc(&mut buffer);
                    if !self.contains_data(&mut buffer) {
                        // update bloom filter with matched txout
                        self.insert_data(buffer.clone());
                    }
                    break;
                }
            }
            n += 1;
        }
    }

    pub fn false_positive_rate(&self) -> f64 {
        f64::powf(1 - f64::powf(E, - 1.0 * self.hash_funcs * self.element_count / (self.length() * 8.0)), self.hash_funcs as f64)
    }

    pub fn length(&self) -> usize {
        self.filter.len()
    }

    pub fn to_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        VarInt(self.length() as u64).enc(&mut buffer);
        self.filter.enc(&mut buffer);
        self.hash_funcs.enc(&mut buffer);
        self.tweak.enc(&mut buffer);
        self.flags.enc(&mut buffer);
        buffer
    }

    pub fn empty_bloom_filter_data() -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        VarInt(0).enc(&mut buffer);
        0u32.enc(&mut buffer);
        0u32.enc(&mut buffer);
        0u8.enc(&mut buffer);
        buffer
    }
}

impl<'a> TryRead<'a, Endian> for BloomFilter {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let filter = bytes.read_with::<VarBytes>(offset, LE)?.1.to_vec();
        let hash_funcs = bytes.read_with::<u32>(offset, LE)?;
        let tweak = bytes.read_with::<u32>(offset, LE)?;
        let flags = bytes.read_with::<u8>(offset, LE)?;
        let data = BloomFilter {
            tweak,
            flags,
            element_count: 0,
            false_positive_rate: 0.0,
            filter,
            hash_funcs
        };
        Ok((data, *offset))
    }
}
