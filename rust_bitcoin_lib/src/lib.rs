use std::ffi::CStr;
use std::str::FromStr;
use std::os::raw::c_char;

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
