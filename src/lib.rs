#![allow(dead_code)]
#![allow(unused_variables)]
#[macro_use]

extern crate core;
#[macro_use] extern crate diesel;

pub extern crate bitcoin_hashes as hashes;
pub extern crate secp256k1;
extern crate core;

pub mod blockdata;
pub mod chain;
pub mod consensus;
pub mod crypto;
pub mod dapi;
pub mod derivation;
pub mod environment;
pub mod ffi;
pub mod keys;
pub mod manager;
pub mod models;
pub mod network;
pub mod notifications;
pub mod platform;
pub mod processing;
pub mod schema;
pub mod storage;
pub mod user_defaults;
pub mod util;

mod test;
mod hash_types;
#[macro_use]
mod internal_macros;
#[macro_use]
mod macros;
pub mod keychain;

#[cfg(feature = "std")]
use std::io;
#[cfg(not(feature = "std"))]
use core2::io;


pub static CHAINS_MANAGER: std::sync::Mutex<manager::ChainsManager> =
    std::sync::Mutex::new(manager::ChainsManager::new());
