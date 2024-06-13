use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;
use std::str::FromStr;
use std::str::Utf8Error;

use bitcoin::bip152::PrefilledTransaction;
use bitcoin::consensus::deserialize_partial;
use bitcoin::Block;
use miniscript::bitcoin::script;
use miniscript::bitcoin::secp256k1::XOnlyPublicKey;
use miniscript::bitcoin::PublicKey;
use miniscript::DescriptorPublicKey;
use miniscript::Miniscript;
use miniscript::Segwitv0;
use miniscript::Tap;

/// Creates a Rust str from a C string.
///
/// # Safety
/// The caller must ensure that the pointer points to a zero-terminated C string.
/// If the pointer is null, this function will panic. A non-zero terminated string
/// will trigger undefined behavior.
unsafe fn c_str_to_str<'a>(input: *const c_char) -> Result<&'a str, Utf8Error> {
    CStr::from_ptr(input).to_str()
}

/// Creates a C string from a Rust str.
///
/// # Safety
/// The caller must ensure that this memory is deallocated after the C string
/// is no longer used. `into_raw` consumes the string and leaks the memory,
/// making this allocation invisible to Rust's memory management.
///
/// This function panics if the input contains an internal null byte.
unsafe fn str_to_c_string(input: &str) -> *mut c_char {
    CString::new(input).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_des_block(data: *const u8, len: usize) -> *mut c_char {
    let data_slice = std::slice::from_raw_parts(data, len);
    let res = deserialize_partial::<Block>(data_slice);

    match res {
        Ok(block) => str_to_c_string(&block.0.block_hash().to_string()),
        Err(err) => {
            if err.to_string().starts_with("unsupported segwit version") {
                return str_to_c_string("unsupported segwit version")
            }
            str_to_c_string("")
        },
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_prefilledtransaction(data: *const u8, len: usize) -> *mut c_char {
    let data_slice = std::slice::from_raw_parts(data, len);
    let res = deserialize_partial::<PrefilledTransaction>(data_slice);

    match res {
        Ok(tx) => str_to_c_string(&tx.0.idx.to_string()),
        Err(err) => {
            if err.to_string().starts_with("unsupported segwit version") {
                return str_to_c_string("unsupported segwit version")
            }
            str_to_c_string("")
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_miniscript_from_str(input: *const c_char) -> bool {
    let Ok(desc) = c_str_to_str(input) else {
        return false;
    };

    match Miniscript::<DescriptorPublicKey, Segwitv0>::from_str(desc) {
        Err(_) => Miniscript::<DescriptorPublicKey, Tap>::from_str(desc).is_ok(),
        Ok(_) => true,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_miniscript_from_script(data: *const u8, len: usize) -> bool {
    // Safety: Ensure that the data pointer is valid for the given length
    let data_slice = slice::from_raw_parts(data, len);

    let script = script::Script::from_bytes(data_slice);
    let desc = Miniscript::<PublicKey, Segwitv0>::parse(&script);

    match desc {
        Err(_) => Miniscript::<XOnlyPublicKey, Tap>::parse(script).is_ok(),
        Ok(_) => true,
    }
}
