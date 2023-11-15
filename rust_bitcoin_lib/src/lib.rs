use std::ffi::CStr;
use std::str::FromStr;
use std::os::raw::c_char;

use miniscript::{Miniscript, Segwitv0};
use miniscript::bitcoin::script;
use miniscript::policy::Concrete;

#[no_mangle]
pub extern "C" fn miniscript_policy(input: *const c_char) -> bool {
    let data = unsafe { CStr::from_ptr(input) }.to_bytes();
    let cstr = String::from_utf8_lossy(data);
    if let Ok(pol) = Concrete::<String>::from_str(&cstr) {
        match pol.is_valid() {
            Ok(_) => true,  // If valid, return true
            Err(_) => false,  // If invalid, return false
        };
    } else {
        return false
    }

    false
}

#[no_mangle]
pub extern "C" fn miniscript_from_script(data: *const u8, len: usize) -> bool {
    // Safety: Ensure that the data pointer is valid for the given length
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };

    let script = script::Script::from_bytes(data_slice);

    if let Ok(pt) = Miniscript::<miniscript::bitcoin::PublicKey, Segwitv0>::parse(script) {
        let output = pt.encode();
        assert_eq!(pt.script_size(), output.len());
    }

    false
}