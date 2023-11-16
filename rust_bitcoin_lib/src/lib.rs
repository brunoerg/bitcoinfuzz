use std::ffi::CStr;
use std::str::FromStr;
use std::os::raw::c_char;

use miniscript::{Miniscript, Segwitv0, bitcoin};
use miniscript::bitcoin::script;
use miniscript::policy::Concrete;

#[no_mangle]
pub extern "C" fn rust_miniscript_policy(input: *const c_char) -> bool {
    if let Ok(data) = unsafe { CStr::from_ptr(input) }.to_str() {
        if let Ok(pol) = Concrete::<String>::from_str(data) {
            match pol.is_valid() {
                Ok(_) => true,
                Err(_) => false,
            };
        } else {
            return false
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn rust_miniscript_from_str(input: *const c_char) -> bool {
    if let Ok(data) = unsafe { CStr::from_ptr(input) }.to_str() {
        if let Ok(_pol) = Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str(data) {
            return true;
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn rust_miniscript_from_script(data: *const u8, len: usize) -> bool {
    // Safety: Ensure that the data pointer is valid for the given length
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };

    let script = script::Script::from_bytes(data_slice);

    if let Ok(pt) = Miniscript::<miniscript::bitcoin::PublicKey, Segwitv0>::parse(script) {
        let output = pt.encode();
        assert_eq!(pt.script_size(), output.len());
    }

    false
}