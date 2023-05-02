#![allow(dead_code)]
#![allow(unused_variables)]
// #[macro_use]

// extern crate core;
#[macro_use] extern crate diesel;
#[macro_use] extern crate bitflags;

pub extern crate bitcoin_hashes as hashes;
pub extern crate secp256k1;

#[cfg(feature = "std")]
use std::io;

#[cfg(not(feature = "std"))]
use core2::io;

#[macro_use]
pub mod internal_macros;
#[macro_use]
pub mod macros;

pub mod blockdata;
pub mod chain;
pub mod consensus;
pub mod crypto;
pub mod dapi;
pub mod derivation;
pub mod environment;
pub mod ffi;
pub mod hash_types;
pub mod keychain;
pub mod keys;
pub mod manager;
pub mod network;
pub mod notifications;
pub mod platform;
pub mod processing;
pub mod resource;
pub mod schema;
pub mod storage;
pub mod user_defaults;
pub mod util;

mod test;


// pub static CHAINS_MANAGER: std::sync::Mutex<manager::ChainsManager> =
//     std::sync::Mutex::new(manager::ChainsManager::new(bip39::Language::English));
