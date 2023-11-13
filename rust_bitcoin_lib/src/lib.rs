use std::ffi::CStr;
use std::str::FromStr;
use std::os::raw::c_char;

use miniscript::{Segwitv0, Miniscript};

#[no_mangle]
pub extern "C" fn miniscript_str_parse(input: *const c_char) -> bool {
    if let Ok(cstr) = unsafe { CStr::from_ptr(input) }.to_str() {
        // Parse the Miniscript
        if let Ok(_desc) = Miniscript::<String, Segwitv0>::from_str(cstr) {
            return true;
        }
    }
    false
}
