use std::ffi::{CStr, CString};
use std::str::FromStr;
use std::os::raw::c_char;

use miniscript::bitcoin::secp256k1::XOnlyPublicKey;
use miniscript::{Miniscript, Segwitv0, Tap};
use miniscript::bitcoin::{script, PublicKey};
use miniscript::policy::Concrete;

#[no_mangle]
pub extern "C" fn rust_bitcoin_des_block(data: *const u8, len: usize) -> *mut std::os::raw::c_char {
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };
    let res: Result<bitcoin::blockdata::block::Block, _> =
        bitcoin::consensus::encode::deserialize(data_slice);

    if res.is_ok() { return CString::new(res.unwrap().block_hash().to_string()).unwrap().into_raw() };

    return CString::new("").unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn rust_miniscript_policy(input: *const c_char) -> bool {
    if let Ok(data) = unsafe { CStr::from_ptr(input) }.to_str() {
        if let Ok(pol) = Concrete::<String>::from_str(data) {
            return pol.is_valid().is_ok()
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn rust_miniscript_from_str(input: *const c_char) -> bool {
    if let Ok(data) = unsafe { CStr::from_ptr(input) }.to_str() {
        if let Ok(_pol) = Miniscript::<String, Segwitv0>::from_str(data) {
            return true
        } else if let Ok(_pol) = Miniscript::<String, Tap>::from_str(data) {
            return true
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn rust_miniscript_from_script(data: *const u8, len: usize) -> bool {
    // Safety: Ensure that the data pointer is valid for the given length
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };

    let script = script::Script::from_bytes(data_slice);

    if let Ok(_pt) = Miniscript::<PublicKey, Segwitv0>::parse(script) {
        return true
    } else if let Ok(_pt) = Miniscript::<XOnlyPublicKey, Tap>::parse(script) {
        return true
    }

    false
}