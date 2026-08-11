use musig2::secp::MaybeScalar;
use musig2::{AggNonce, BinaryEncoding, KeyAggContext, PartialSignature, PubNonce, SecNonce};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::ffi::CString;
use std::os::raw::c_char;
use std::{ptr, slice};

/// Derives a public key per scalar and aggregates them into one MuSig2 key.
///
/// # Arguments
/// * `seckeys` - Pointer to concatenated 32-byte private keys
/// * `num_keys` - Number of private keys to aggregate
///
/// # Returns
/// * Hex-encoded 33-byte compressed aggregated public key on success;
/// * the "AGG_FAIL" sentinel if aggregation itself is rejected (so the C++
///   driver compares it against the peer module and catches accept-vs-reject
///   disagreements);
/// * null if an input scalar is invalid (symmetric, skipped by the driver).
///
/// # Safety
/// Caller must ensure `seckeys` points to valid memory of size `num_keys * 32`
#[no_mangle]
pub unsafe extern "C" fn musig2_key_agg(seckeys: *const u8, num_keys: usize) -> *mut c_char {
    if seckeys.is_null() || num_keys == 0 || num_keys > 100 {
        return ptr::null_mut();
    }

    let seckeys_slice = slice::from_raw_parts(seckeys, num_keys * 32);
    let secp = Secp256k1::new();

    // Derive a pubkey for each 32-byte scalar, preserving input order: BIP-327
    // key aggregation is order-sensitive (sorting is a separate, optional step).
    let mut parsed_pubkeys: Vec<PublicKey> = Vec::with_capacity(num_keys);
    for i in 0..num_keys {
        let start = i * 32;
        let end = start + 32;
        let seckey_bytes: [u8; 32] = match seckeys_slice[start..end].try_into() {
            Ok(arr) => arr,
            Err(_) => return ptr::null_mut(),
        };
        let seckey = match SecretKey::from_byte_array(seckey_bytes) {
            Ok(sk) => sk,
            Err(_) => return ptr::null_mut(),
        };
        parsed_pubkeys.push(PublicKey::from_secret_key(&secp, &seckey));
    }

    // Aggregate the public keys using musig2
    let key_agg_ctx = match KeyAggContext::new(parsed_pubkeys) {
        Ok(ctx) => ctx,
        Err(_) => return str_to_c_string("AGG_FAIL"),
    };

    // Get the aggregated public key (includes parity)
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

    // Serialize to compressed format (33 bytes with 02/03 prefix)
    let serialized = aggregated_pubkey.serialize();
    let hex_result = hex::encode(serialized);

    str_to_c_string(&hex_result)
}

/// Runs a complete MuSig2 signing session, mirroring the `secp256k1` module's
/// `secp256k1_musig2_sign_session` so the C++ driver can compare the two
/// byte-for-byte at every stage.
///
/// Each signer's nonce is derived deterministically from its 32-byte
/// `nonce_seeds` entry exactly as BIP327 / libsecp256k1's
/// `secp256k1_musig_nonce_gen` does:
/// * the *untweaked* aggregate pubkey is hashed in (tweaks are applied only
///   afterwards, on the key-agg context used for signing), and
/// * when `extra_input32` is null an **empty** extra input is supplied so that
///   the BIP327 nonce hash includes a 4-byte zero length prefix, matching how
///   libsecp256k1 encodes a `NULL` `extra_input32`. Omitting it entirely would
///   write nothing and yield a different nonce (and thus a different,
///   spuriously-mismatching signature).
///
/// Pubnonces, the aggnonce and partial signatures are serialize/parse
/// roundtripped mid-session so the parsers are exercised with honest values,
/// matching the secp256k1 module.
///
/// # Arguments
/// * `seckeys` - `num_keys` concatenated 32-byte private keys
/// * `num_keys` - number of signers
/// * `msg32` - the 32-byte message being signed
/// * `nonce_seeds` - `num_keys` concatenated 32-byte nonce seeds (one per signer)
/// * `extra_input32` - null, or 32 bytes mixed into nonce generation
/// * `tweaks` - `num_tweaks` records of 33 bytes each: a type byte (non-zero
///   for x-only, zero for plain) followed by the 32-byte tweak, applied in
///   order
///
/// # Returns
/// * "aggnonce:partial_sig1,...,partial_sigN:final_sig" in hex on success;
/// * a sentinel string ("AGG_FAIL", "NONCE_GEN_FAIL", "TWEAK_FAIL",
///   "PARTIAL_SIGN_FAIL", "PARTIAL_SIG_AGG_FAIL") when a step is rejected, so
///   the driver catches accept-vs-reject disagreements against the peer
///   module;
/// * null when an input scalar is invalid (symmetric with secp256k1 returning
///   nullopt, which the driver skips).
///
/// # Safety
/// `seckeys` and `nonce_seeds` must point to `num_keys * 32` valid bytes,
/// `msg32` to 32 bytes, `extra_input32` to 32 bytes when non-null, and
/// `tweaks` to `num_tweaks * 33` bytes when `num_tweaks > 0`.
#[no_mangle]
pub unsafe extern "C" fn musig2_sign_session(
    seckeys: *const u8,
    num_keys: usize,
    msg32: *const u8,
    nonce_seeds: *const u8,
    extra_input32: *const u8,
    tweaks: *const u8,
    num_tweaks: usize,
) -> *mut c_char {
    if seckeys.is_null()
        || msg32.is_null()
        || nonce_seeds.is_null()
        || num_keys == 0
        || num_keys > 100
    {
        return ptr::null_mut();
    }

    let seckeys_slice = slice::from_raw_parts(seckeys, num_keys * 32);
    let nonce_seeds_slice = slice::from_raw_parts(nonce_seeds, num_keys * 32);
    let msg: [u8; 32] = match slice::from_raw_parts(msg32, 32).try_into() {
        Ok(arr) => arr,
        Err(_) => return ptr::null_mut(),
    };
    let secp = Secp256k1::new();

    // Parse each scalar and derive its pubkey, preserving input order (BIP327
    // key aggregation is order-sensitive). An invalid scalar -> null (skipped).
    let mut seckey_objs: Vec<SecretKey> = Vec::with_capacity(num_keys);
    let mut pubkey_objs: Vec<PublicKey> = Vec::with_capacity(num_keys);
    for i in 0..num_keys {
        let seckey_bytes: [u8; 32] = match seckeys_slice[i * 32..(i + 1) * 32].try_into() {
            Ok(arr) => arr,
            Err(_) => return ptr::null_mut(),
        };
        let seckey = match SecretKey::from_byte_array(seckey_bytes) {
            Ok(sk) => sk,
            Err(_) => return ptr::null_mut(),
        };
        pubkey_objs.push(PublicKey::from_secret_key(&secp, &seckey));
        seckey_objs.push(seckey);
    }

    let key_agg_ctx = match KeyAggContext::new(pubkey_objs) {
        Ok(ctx) => ctx,
        Err(_) => return str_to_c_string("AGG_FAIL"),
    };

    // Capture the untweaked aggregate pubkey for nonce generation before any
    // tweaks are applied (libsecp256k1 generates nonces against the untweaked
    // key, then tweaks the key-agg cache used for signing).
    let untweaked_agg: PublicKey = key_agg_ctx.aggregated_pubkey();

    // Round 1: deterministic nonce generation per signer.
    let extra_input: &[u8] = if extra_input32.is_null() {
        // Empty slice matches libsecp256k1's NULL extra_input32 (zero-length
        // prefix in the BIP327 nonce hash).
        &[]
    } else {
        slice::from_raw_parts(extra_input32, 32)
    };
    let mut secnonces: Vec<SecNonce> = Vec::with_capacity(num_keys);
    let mut pubnonces: Vec<PubNonce> = Vec::with_capacity(num_keys);
    for i in 0..num_keys {
        let nonce_seed: [u8; 32] = nonce_seeds_slice[i * 32..(i + 1) * 32]
            .try_into()
            .expect("32-byte chunk");
        if nonce_seed.iter().all(|&b| b == 0) {
            return str_to_c_string("NONCE_GEN_FAIL");
        }
        let secnonce = SecNonce::build_with_seckey(nonce_seed, seckey_objs[i])
            .with_message(&msg)
            .with_aggregated_pubkey(untweaked_agg)
            .with_extra_input(&extra_input)
            .build();
        // Roundtrip serialize/parse and continue the session on the parser's
        // output, so the parser is exercised with honest values.
        let pubnonce = match PubNonce::from_bytes(&secnonce.public_nonce().serialize()) {
            Ok(pn) => pn,
            Err(_) => return str_to_c_string("NONCE_GEN_FAIL"),
        };
        pubnonces.push(pubnonce);
        secnonces.push(secnonce);
    }

    let aggnonce: AggNonce = pubnonces.iter().sum();
    // The serialized aggnonce is part of the compared response, so a nonce
    // derivation divergence is caught (and pinpointed) even when the final
    // signatures happen to match. Reparse it so the session runs on the
    // parser's output.
    let aggnonce_ser = aggnonce.serialize();
    let aggnonce = match AggNonce::from_bytes(&aggnonce_ser) {
        Ok(an) => an,
        Err(_) => return str_to_c_string("NONCE_AGG_FAIL"),
    };

    let key_agg_ctx = match apply_tweaks(key_agg_ctx, tweaks, num_tweaks) {
        Some(ctx) => ctx,
        None => return str_to_c_string("TWEAK_FAIL"),
    };

    // Round 2: each signer produces a partial signature over the tweaked key.
    let mut partial_sigs: Vec<PartialSignature> = Vec::with_capacity(num_keys);
    let mut partial_sigs_hex: Vec<String> = Vec::with_capacity(num_keys);
    for (i, secnonce) in secnonces.into_iter().enumerate() {
        let partial_sig: PartialSignature =
            match musig2::sign_partial(&key_agg_ctx, seckey_objs[i], secnonce, &aggnonce, msg) {
                Ok(sig) => sig,
                Err(_) => return str_to_c_string("PARTIAL_SIGN_FAIL"),
            };
        // Roundtrip serialize/parse and aggregate the parser's output; the
        // hex also goes into the compared response.
        let partial_sig_ser = partial_sig.serialize();
        let partial_sig = match PartialSignature::try_from(&partial_sig_ser[..]) {
            Ok(sig) => sig,
            Err(_) => return str_to_c_string("PARTIAL_SIGN_FAIL"),
        };
        partial_sigs_hex.push(hex::encode(partial_sig_ser));
        partial_sigs.push(partial_sig);
    }

    let final_sig: [u8; 64] =
        match musig2::aggregate_partial_signatures(&key_agg_ctx, &aggnonce, partial_sigs, msg) {
            Ok(sig) => sig,
            Err(_) => return str_to_c_string("PARTIAL_SIG_AGG_FAIL"),
        };

    let response = format!(
        "{}:{}:{}",
        hex::encode(aggnonce_ser),
        partial_sigs_hex.join(","),
        hex::encode(final_sig)
    );
    str_to_c_string(&response)
}

/// Applies `num_tweaks` packed 33-byte tweak records (type byte, non-zero for
/// x-only, followed by the 32-byte tweak) to a key-agg context in input
/// order, matching the secp256k1 module. Returns `None` if a tweak scalar is
/// invalid or rejected, which the caller maps to the "TWEAK_FAIL" sentinel.
unsafe fn apply_tweaks(
    mut ctx: KeyAggContext,
    tweaks: *const u8,
    num_tweaks: usize,
) -> Option<KeyAggContext> {
    if num_tweaks == 0 {
        return Some(ctx);
    }
    if tweaks.is_null() {
        return None;
    }
    let records = slice::from_raw_parts(tweaks, num_tweaks * 33);
    for record in records.chunks_exact(33) {
        let tweak = MaybeScalar::try_from(&record[1..33]).ok()?;
        ctx = if record[0] != 0 {
            ctx.with_xonly_tweak(tweak).ok()?
        } else {
            ctx.with_plain_tweak(tweak).ok()?
        };
    }
    Some(ctx)
}

/// Deserializes a MuSig2 KeyAggContext and verifies that parse/serialize is
/// idempotent.
///
/// The binary format (KeyAggContext::to_bytes) is: a header byte (bit 0 =
/// negate aggregated pubkey parity, bit 1 = tweak accumulator present), an
/// optional 32-byte tweak accumulator, a 4-byte big-endian pubkey count, and
/// one 33-byte compressed pubkey per participant.
///
/// # Returns
/// * "DECODE_ERR" if the bytes are rejected;
/// * "ROUNDTRIP_FAIL:<detail>" if parsing succeeded but re-serializing and
///   re-parsing is not the identity (a library invariant violation; the C++
///   driver treats this sentinel as fatal even with a single module);
/// * "<aggpub_hex>;<ser_hex>" — the aggregated compressed pubkey and the
///   canonical serialization — on success.
///
/// A panic inside the parser (e.g. the empty-set assertion reachable with a
/// wrapped pubkey count on 32-bit targets) aborts the process and is caught
/// by libFuzzer as a crash, which is the intended behavior for this target.
///
/// # Safety
/// Caller must ensure `data` points to `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn musig2_keyagg_ctx(data: *const u8, len: usize) -> *mut c_char {
    if data.is_null() {
        return ptr::null_mut();
    }
    let bytes = slice::from_raw_parts(data, len);

    let ctx = match KeyAggContext::from_bytes(bytes) {
        Ok(ctx) => ctx,
        Err(_) => return str_to_c_string("DECODE_ERR"),
    };

    let ser1 = ctx.to_bytes();
    match KeyAggContext::from_bytes(&ser1) {
        Ok(ctx2) if ctx2.to_bytes() == ser1 => {}
        Ok(ctx2) => {
            return str_to_c_string(&format!(
                "ROUNDTRIP_FAIL:re-serialization changed:{}:{}",
                hex::encode(&ser1),
                hex::encode(ctx2.to_bytes())
            ));
        }
        Err(_) => {
            return str_to_c_string(&format!(
                "ROUNDTRIP_FAIL:re-parse rejected:{}",
                hex::encode(&ser1)
            ));
        }
    }

    let aggregated_pubkey: PublicKey = ctx.aggregated_pubkey();
    str_to_c_string(&format!(
        "{}:{}",
        hex::encode(aggregated_pubkey.serialize()),
        hex::encode(&ser1)
    ))
}

/// Frees a string allocated by this library.
///
/// # Safety
/// Caller must ensure `ptr` was allocated by this library's functions.
#[no_mangle]
pub unsafe extern "C" fn musig2_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

unsafe fn str_to_c_string(input: &str) -> *mut c_char {
    match CString::new(input) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}
