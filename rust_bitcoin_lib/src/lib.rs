use std::ffi::CStr;
use std::str::FromStr;
use std::os::raw::c_char;

use miniscript::bitcoin::secp256k1::XOnlyPublicKey;
use miniscript::{Miniscript, Segwitv0, bitcoin, Tap};
use miniscript::bitcoin::{script, PublicKey};
use miniscript::policy::Concrete;

#[no_mangle]
pub extern "C" fn rust_miniscript_policy(input: *const c_char) -> bool {
    if let Ok(data) = unsafe { CStr::from_ptr(input) }.to_str() {
        if let Ok(_pol) = Concrete::<String>::from_str(data) {
            return true
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