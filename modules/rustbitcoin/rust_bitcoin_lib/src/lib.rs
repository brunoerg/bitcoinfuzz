use bitcoin::address::Address;
use bitcoin::bip32::AbsoluteDerivationPath;
use bitcoin::bip32::Bip32Seed;
use bitcoin::bip32::ChainCode;
use bitcoin::bip32::ChildNumber;
use bitcoin::bip32::Fingerprint;
use bitcoin::bip32::RelativeDerivationPath;
use bitcoin::bip32::Xpriv;
use bitcoin::bip32::Xpub;
use bitcoin::consensus::{deserialize_partial, encode};
use bitcoin::encoding::{decode_from_slice, decode_from_slice_unbounded, encode_to_vec};
use bitcoin::script::ScriptExt;
use bitcoin::script::ScriptPubKeyBuf;
use bitcoin::script::ScriptPubKeyExt;
use bitcoin::secp256k1::ellswift::ElligatorSwift;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::Block;
use bitcoin::NetworkKind;
use p2p::address::AddrV2;
use p2p::bip152::HeaderAndShortIds;
use p2p::message::{AddrV2Payload, V1NetworkMessage};
use p2p::Magic;
use std::ffi::CStr;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::str::{FromStr, Utf8Error};

unsafe fn str_to_c_string(input: &str) -> *mut c_char {
    CString::new(input).unwrap().into_raw()
}

/// Returns true if `needle` appears in the `Display` output of `err` or any of
/// its sources.
///
/// The new `bitcoin-consensus-encoding` errors wrap inner decode errors and
/// (with the `std` feature) only render their own top-level message via
/// `Display`, exposing the underlying cause through `Error::source()`. Matching
/// against a single `to_string()` is therefore unreliable, so we walk the whole
/// source chain.
fn error_chain_contains(err: &dyn std::error::Error, needle: &str) -> bool {
    let mut current: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = current {
        if e.to_string().contains(needle) {
            return true;
        }
        current = e.source();
    }
    false
}

/// Frees a C string created by `str_to_c_string`.
///
/// # Safety
/// The pointer must have been created by `str_to_c_string` and not yet freed.
/// After calling this function, the pointer is invalid and must not be used.
#[no_mangle]
pub unsafe extern "C" fn free_c_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // Convert the raw pointer back to a CString, which will be dropped
        // and free the memory when it goes out of scope
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_des_block(
    data: *const u8,
    len: usize,
    _out_len: *mut usize,
) -> *mut c_char {
    let data_slice = std::slice::from_raw_parts(data, len);
    let res = deserialize_partial::<Block>(data_slice);

    match res {
        Ok(res) => {
            let block = match res.0.validate() {
                Ok(block_checked) => block_checked,
                Err(_) => return str_to_c_string("0"),
            };
            let block_hash = block.block_hash();
            return str_to_c_string(&block_hash.to_string());
        }
        Err(err) => {
            if err.to_string().starts_with("unsupported SegWit version") {
                return str_to_c_string("skip error");
            }
            if err
                .to_string()
                .starts_with("parse failed: amount is greater than Amount::MAX_MONEY")
            {
                return str_to_c_string("skip error");
            }
            return str_to_c_string("0");
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_script(data: *const u8, len: usize) -> *mut c_char {
    // Safety: Ensure that the data pointer is valid for the given length
    let data_slice = slice::from_raw_parts(data, len);

    let script: Result<(ScriptPubKeyBuf, usize), encode::ParseError> =
        encode::deserialize_partial(data_slice);
    match script {
        Err(_) => str_to_c_string("0"),
        Ok(s) => {
            if s.0.is_op_return() || s.0.len() > 10_000 {
                return str_to_c_string("0");
            }
            let mut final_res = s.0.count_sigops_legacy().to_string();
            final_res.push_str(if s.0.is_witness_program() { "1" } else { "0" });
            final_res.push_str(if s.0.is_push_only() { "1" } else { "0" });
            str_to_c_string(&final_res)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_parse_p2p_message(
    data: *const u8,
    len: usize,
) -> *mut c_char {
    let data_slice = slice::from_raw_parts(data, len);

    let message: V1NetworkMessage = match decode_from_slice(data_slice) {
        Ok(m) => m,
        Err(_) => return str_to_c_string("0"),
    };

    if message.magic() != &Magic::BITCOIN {
        return str_to_c_string("0");
    }

    let cmd = message.cmd();
    match cmd {
        "unknown" => str_to_c_string("0"),
        _ => str_to_c_string(cmd),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_address_parse(address: *const c_char) -> *mut c_char {
    if address.is_null() {
        return std::ptr::null_mut();
    }

    let address_str = match c_str_to_str(address) {
        Ok(s) => s,
        Err(_) => return str_to_c_string("INVALID"),
    };

    match Address::from_str(address_str) {
        Ok(addr_unchecked) => match addr_unchecked.require_network(bitcoin::Network::Bitcoin) {
            Ok(addr) => {
                let prefix = match addr.address_type() {
                    Some(bitcoin::address::AddressType::P2pkh) => "PKH:",
                    Some(bitcoin::address::AddressType::P2sh) => "SH:",
                    Some(bitcoin::address::AddressType::P2wpkh) => "WPKH:",
                    Some(bitcoin::address::AddressType::P2wsh) => "WSH:",
                    Some(bitcoin::address::AddressType::P2tr) => "TR:",
                    Some(_) => "UNK:",
                    None => "UNK:",
                };

                let result = format!("{}{:}", prefix, addr);
                str_to_c_string(&result)
            }
            Err(_) => str_to_c_string("INVALID"),
        },
        Err(_) => str_to_c_string("INVALID"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_psbt_parse(_data: *const u8, _len: usize) -> *mut c_char {
    // PSBT support was extracted out of the `bitcoin` crate (into the
    // separately-versioned `rust-psbt`) and is no longer available at this
    // revision. Returning null makes the driver skip this module for the PSBT
    // target instead of comparing against a value we can no longer produce.
    std::ptr::null_mut()
}

/// Converts AddrV2 to hex string representation of its raw bytes
fn addrv2_to_hex(addr: &AddrV2) -> String {
    match addr {
        AddrV2::Ipv4(ip) => ip.octets().iter().map(|b| format!("{:02x}", b)).collect(),
        AddrV2::Ipv6(ip) => ip.octets().iter().map(|b| format!("{:02x}", b)).collect(),
        AddrV2::TorV3(bytes) => bytes.iter().map(|b| format!("{:02x}", b)).collect(),
        AddrV2::I2p(bytes) => bytes.iter().map(|b| format!("{:02x}", b)).collect(),
        AddrV2::Cjdns(ip) => ip.octets().iter().map(|b| format!("{:02x}", b)).collect(),
        AddrV2::Unknown(network_id, bytes) => {
            format!(
                "{:02x}:{}",
                network_id,
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            )
        }
    }
}

/// Returns the type string for an AddrV2 address
fn addrv2_type(addr: &AddrV2) -> &'static str {
    match addr {
        AddrV2::Ipv4(_) => "ipv4",
        AddrV2::Ipv6(_) => "ipv6",
        AddrV2::TorV3(_) => "tor",
        AddrV2::I2p(_) => "i2p",
        AddrV2::Cjdns(_) => "cjdns",
        AddrV2::Unknown(_, _) => "unknown",
    }
}

fn is_routable_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 0.0.0.0/8 - "This" network
    if octets[0] == 0 {
        return false;
    }

    // Loopback, broadcast, private (RFC 1918)
    if ip.is_loopback() || ip.is_broadcast() || ip.is_private() {
        return false;
    }

    // RFC 2544 - Benchmarking - 198.18.0.0/15
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }

    // RFC 3927 - Link-Local - 169.254.0.0/16
    if ip.is_link_local() {
        return false;
    }

    // RFC 6598 - Shared Address Space (CGNAT) - 100.64.0.0/10
    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
        return false;
    }

    // RFC 5737 - Documentation (TEST-NET-1, TEST-NET-2, TEST-NET-3)
    if ip.is_documentation() {
        return false;
    }

    true
}

fn is_routable_ipv6(ip: &Ipv6Addr) -> bool {
    let octets = ip.octets();

    // Unspecified, loopback, unique local (RFC 4193 - fc00::/7)
    if ip.is_unspecified() || ip.is_loopback() || ip.is_unique_local() {
        return false;
    }

    // RFC 4843 - ORCHID - 2001:10::/28
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x00 && (octets[3] & 0xF0) == 0x10 {
        return false;
    }

    // RFC 4862 - Link-local - fe80::/64
    if octets[..8] == [0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
        return false;
    }

    // RFC 7343 - ORCHIDv2 - 2001:20::/28
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x00 && (octets[3] & 0xf0) == 0x20 {
        return false;
    }

    true
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_addrv2(data: *const u8, len: usize) -> *mut c_char {
    // Safety: Ensure that the data pointer is valid for the given length
    let data_slice = slice::from_raw_parts(data, len);

    let mut cursor = data_slice;
    let addr = decode_from_slice_unbounded::<AddrV2Payload>(&mut cursor);
    match addr {
        Err(e) => {
            if error_chain_contains(&e, "CJDNS") || error_chain_contains(&e, "wrapped IPv4") {
                return std::ptr::null_mut();
            }
            str_to_c_string("[]")
        }
        Ok(payload) => {
            let mut entries: Vec<String> = Vec::new();
            for a in payload.0 {
                if matches!(a.addr, AddrV2::Unknown(..)) {
                    continue;
                }
                // Match the same behavior as isRoutable() function from core.
                if let AddrV2::Ipv4(ip) = &a.addr {
                    if !is_routable_ipv4(ip) {
                        continue;
                    }
                }
                if let AddrV2::Ipv6(ip) = &a.addr {
                    if !is_routable_ipv6(ip) {
                        continue;
                    }
                }
                let addr_hex = addrv2_to_hex(&a.addr);
                let addr_type = addrv2_type(&a.addr);
                let time = a.time;
                let services = a.services.to_u64();
                let port = a.port;
                entries.push(format!(
                    "{{\"addr\":\"{}\",\"type\":\"{}\",\"time\":\"{}\",\"services\":\"{}\",\"port\":\"{}\"}}",
                    addr_hex, addr_type, time, services, port
                ));
            }
            let result = format!("[{}]", entries.join(","));
            str_to_c_string(&result)
        }
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_cmpctblocks_parse(
    data: *const u8,
    len: usize,
) -> *mut c_char {
    // Safety: Ensure that the data pointer is valid for the given length
    let data_slice = slice::from_raw_parts(data, len);

    let mut cursor = data_slice;
    match decode_from_slice_unbounded::<HeaderAndShortIds>(&mut cursor) {
        Ok(header_and_short_ids) => {
            if !cursor.is_empty() {
                return str_to_c_string("ERR:trailing_bytes");
            }
            if header_and_short_ids
                .prefilled_txs
                .iter()
                .any(|prefilled_tx| prefilled_tx.tx.inputs.is_empty())
            {
                return ptr::null_mut();
            }
            let serialized_data = encode_to_vec(&header_and_short_ids);
            let result = format!(
                "OK:header={};tx_count={};ser={}",
                header_and_short_ids.header.block_hash(),
                header_and_short_ids.short_ids.len() + header_and_short_ids.prefilled_txs.len(),
                hex_encode(&serialized_data)
            );
            str_to_c_string(&result)
        }
        Err(err) => {
            if error_chain_contains(&err, "segwit flag") {
                return ptr::null_mut();
            }
            str_to_c_string("ERR:parse")
        }
    }
}

/// Computes the merkle root over a list of raw 32-byte hashes (internal byte
/// order, concatenated). Prints the root in display byte order.
///
/// `TxMerkleNode::calculate_root` returns `None` for empty lists and for
/// lists containing the consecutive duplicates that trigger CVE-2012-2459.
/// The driver never feeds empty lists, so `None` here maps to the "REJECTED"
/// sentinel: refusing to compute a mutated root is treated as agreeing with
/// modules that compute the root but report `mutated=1` (Bitcoin Core,
/// gocoin).
#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_merkle_root_compute(
    data: *const u8,
    len: usize,
) -> *mut c_char {
    if len % 32 != 0 {
        return ptr::null_mut();
    }

    let data_slice = slice::from_raw_parts(data, len);
    let leaves = data_slice
        .chunks_exact(32)
        .map(|chunk| bitcoin::Txid::from_byte_array(chunk.try_into().expect("chunk of 32 bytes")));

    match bitcoin::merkle_tree::TxMerkleNode::calculate_root(leaves) {
        Some(root) => str_to_c_string(&format!("{};mutated=0", root)),
        None => str_to_c_string("REJECTED"),
    }
}

/// Parses a BIP37 partial Merkle tree (nTransactions | hashes | flag bytes)
/// and extracts the matched transactions, mirroring Bitcoin Core's
/// CPartialMerkleTree::ExtractMatches. Trailing bytes are tolerated, matching
/// Core's DataStream behavior. Rejection reasons are normalized to "REJECT"
/// because Core collapses all of them into a zero-hash return.
#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_partial_merkle_tree(
    data: *const u8,
    len: usize,
) -> *mut c_char {
    let data_slice = slice::from_raw_parts(data, len);
    let mut cursor = data_slice;
    let pmt = match decode_from_slice_unbounded::<p2p::merkle_tree::PartialMerkleTree>(&mut cursor)
    {
        Ok(pmt) => pmt,
        Err(_) => return str_to_c_string("PARSE_ERR"),
    };

    let mut matches: Vec<bitcoin::Txid> = Vec::new();
    let mut indexes: Vec<u32> = Vec::new();
    match pmt.extract_matches(&mut matches, &mut indexes) {
        Err(_) => str_to_c_string("REJECT"),
        Ok(root) => {
            // Core signals every extraction failure with the zero hash, so a
            // zero root is indistinguishable from rejection in its API (and
            // is treated as rejection by all its callers); map to the same
            // sentinel for comparability.
            if root == bitcoin::TxMerkleNode::from_byte_array([0u8; 32]) {
                return str_to_c_string("REJECT");
            }
            let mut result = format!("{};m=", root);
            for (i, (txid, idx)) in matches.iter().zip(indexes.iter()).enumerate() {
                if i > 0 {
                    result.push(',');
                }
                result.push_str(&format!("{}@{}", txid, idx));
            }
            str_to_c_string(&result)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_bip32_master_keygen(
    data: *const u8,
    len: usize,
) -> *mut c_char {
    let seed = slice::from_raw_parts(data, len);
    // `new_master` now requires a validated `Bip32Seed` (16..=64 bytes). For
    // out-of-range lengths we can no longer produce a key, so skip this module
    // (return null) instead of comparing against a value we can't compute.
    let seed = match <&Bip32Seed>::try_from(seed) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let sk = Xpriv::new_master(NetworkKind::Main, seed);
    str_to_c_string(&sk.to_string())
}

unsafe fn c_str_to_str<'a>(input: *const c_char) -> Result<&'a str, Utf8Error> {
    CStr::from_ptr(input).to_str()
}

//helper func
fn format_ext_key_common(
    depth: u8,
    fingerprint: Fingerprint,
    child_number: ChildNumber,
    chain_code: ChainCode,
    key_bytes: &[u8],
) -> String {
    let hex_key_bytes: String = key_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let child_u32: u32 = child_number.into();
    format!(
        "depth={:02x};fp={:02x}{:02x}{:02x}{:02x};child={:08x};chaincode={};key={}",
        depth,
        fingerprint[0],
        fingerprint[1],
        fingerprint[2],
        fingerprint[3],
        child_u32,
        chain_code,
        hex_key_bytes
    )
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_bip32_deserialize_extended_key(
    data: *const u8,
    len: usize,
) -> *mut c_char {
    let data_slice = slice::from_raw_parts(data, len);
    let ext_str = match std::str::from_utf8(data_slice) {
        Ok(s) => s,
        Err(_) => return str_to_c_string("INVALID"),
    };
    if let Ok(xprv) = Xpriv::from_str(&ext_str) {
        //format the result to string
        let result = format_ext_key_common(
            xprv.depth,
            xprv.parent_fingerprint,
            xprv.child_number,
            xprv.chain_code,
            &xprv.private_key.to_secret_bytes(), // as bytes
        );
        //return formatted string
        str_to_c_string(&result)
    } else {
        if let Ok(xpub) = Xpub::from_str(&ext_str) {
            //format the result to string
            let result = format_ext_key_common(
                xpub.depth,
                xpub.parent_fingerprint,
                xpub.child_number,
                xpub.chain_code,
                &xpub.public_key.serialize(), // as bytes
            );
            //return formatted string
            str_to_c_string(&result)
        } else {
            str_to_c_string("INVALID")
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_bip32_derive_from_path(
    data: *const u8,
    len: usize,
) -> *mut c_char {
    let data_slice = slice::from_raw_parts(data, len);
    let path_str = match std::str::from_utf8(data_slice) {
        Ok(s) => s,
        Err(_) => return str_to_c_string("INVALID"),
    };

    // if buffer contains a '+', SKIP
    if path_str.as_bytes().iter().any(|&b| b == b'+') {
        return ptr::null_mut();
    }

    // if buffer contains a trailing slash, SKIP
    if path_str.as_bytes().last() == Some(&b'/') {
        return ptr::null_mut();
    }

    // if buffer contains a whitespace, SKIP
    if path_str.chars().any(|c| c.is_whitespace()) {
        return ptr::null_mut();
    }

    // if index is too large (> 0x7FFFFFFF), SKIP
    let mut start = 0usize;
    let path_bytes = path_str.as_bytes();

    while start < path_bytes.len() {
        let mut end = start;
        while end < path_bytes.len() && path_bytes[end] != b'/' {
            end += 1;
        }

        let part = &path_str[start..end];

        // strip trailing '\'' or 'h' if present
        let part = part
            .strip_suffix('\'')
            .or_else(|| part.strip_suffix('h'))
            .unwrap_or(part);

        if !part.is_empty() {
            if let Ok(val) = part.parse::<u64>() {
                if val > 0x7FFF_FFFF {
                    return ptr::null_mut();
                }
            }
        }

        if end == path_bytes.len() {
            break;
        }
        start = end + 1;
    }

    // The old `DerivationPath` accepted both absolute ("m/0'/1") and relative
    // ("0'/1") notation. That type was split into `AbsoluteDerivationPath` and
    // `RelativeDerivationPath`, so try the absolute form first and fall back to
    // the relative one to preserve the previous behavior.
    let path = match AbsoluteDerivationPath::from_str(path_str) {
        Ok(abs) => abs.into_relative(),
        Err(_) => match RelativeDerivationPath::from_str(path_str) {
            Ok(rel) => rel,
            Err(_) => return str_to_c_string("INVALID"),
        },
    };

    if path.as_ref().is_empty() {
        return str_to_c_string("INVALID");
    }

    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let master_key = Xpriv::new_master(NetworkKind::Main, &seed);
    match master_key.derive_priv(&path) {
        Ok(derived_key) => str_to_c_string(&derived_key.to_string()),
        Err(_) => str_to_c_string("INVALID"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_decode_ellswift(data: *const u8, len: usize) -> *mut c_char {
    if data.is_null() || len != 64 {
        return ptr::null_mut();
    }

    let encoded_bytes: [u8; 64] = slice::from_raw_parts(data, len).try_into().unwrap();
    let encoded = ElligatorSwift::from_array(encoded_bytes);
    let public_key = PublicKey::from_ellswift(encoded);
    str_to_c_string(&public_key.to_string())
}

#[no_mangle]
pub unsafe extern "C" fn rust_bitcoin_roundtrip_ellswift(
    data: *const u8,
    len: usize,
) -> *mut c_char {
    if data.is_null() || len != 32 {
        return ptr::null_mut();
    }

    let secret_bytes: [u8; 32] = slice::from_raw_parts(data, len).try_into().unwrap();
    let secret_key = match SecretKey::from_secret_bytes(secret_bytes) {
        Ok(secret_key) => secret_key,
        Err(_) => return ptr::null_mut(),
    };

    let encoded = ElligatorSwift::from_seckey(secret_key, None);
    let public_key = PublicKey::from_ellswift(encoded);
    str_to_c_string(&public_key.to_string())
}
