use std::collections::HashSet;
use std::fmt::Write;
use byte::BytesExt;
use crate::consensus::Encodable;
use crate::crypto::UInt256;

pub const DASH_MESSAGE_MAGIC: &str = "DarkCoin Signed Message:\n";

pub trait Data {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
    fn true_bits_count(&self) -> u64;
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
    for a in data.iter() {
        write!(s, "{:02x}", a).expect("Can't get hex_with_data");
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

#[inline]
pub fn merkle_root_from_hashes(hashes: Vec<UInt256>) -> Option<UInt256> {
    let length = hashes.len();
    let mut level = hashes.clone();
    if length == 0 { return None; }
    if length == 1 { return Some(hashes[0]); }
    while level.len() != 1 {
        let len = level.len();
        let capacity = (0.5 * len as f64).round();
        let mut higher_level: Vec<UInt256> = Vec::with_capacity(capacity as usize);
        for i in (0..len).step_by(2) {
            let mut buffer: Vec<u8> = Vec::with_capacity(64);
            let left = level[i];
            left.enc(&mut buffer);
            if level.len() - i > 1 {
                level[i+1]
            } else {
                left
            }.enc(&mut buffer);
            higher_level.push(UInt256::sha256d(&buffer));
        }
        level = higher_level;
    }
    Some(level[0])
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


#[inline]
pub fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
    use secp256k1::rand;
    use secp256k1::rand::distributions::Uniform;
    use secp256k1::rand::Rng;
    let mut rng = rand::thread_rng();
    let range = Uniform::new(0, 255);
    (0..size).map(|_| rng.sample(&range)).collect()
}


