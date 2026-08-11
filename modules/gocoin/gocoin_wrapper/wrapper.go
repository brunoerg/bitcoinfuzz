package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    char* data;
    int length;
} ByteArray;
*/
import "C"
import (
	"bytes"
	"unsafe"

	"github.com/piotrnar/gocoin/lib/btc"
	"github.com/piotrnar/gocoin/lib/script"
)

//export GocoinVerifyTxScript
func GocoinVerifyTxScript(scriptSig C.ByteArray, scriptPubKey C.ByteArray) C.int {
	script.DBG_ERR = false
	script_sig := C.GoBytes(unsafe.Pointer(scriptSig.data), C.int(scriptSig.length))
	if len(script_sig) == 0 {
		return 0
	}

	script_pubkey := C.GoBytes(unsafe.Pointer(scriptPubKey.data), C.int(scriptPubKey.length))
	if len(script_pubkey) == 0 {
		return 0
	}

	tx := new(btc.Tx)
	tx.Version = 1
	tx.Lock_time = 0

	var dummyHash [32]byte

	tx.TxIn = make([]*btc.TxIn, 1)
	tx.TxIn[0] = &btc.TxIn{
		Input: btc.TxPrevOut{
			Hash: dummyHash,
			Vout: 0,
		},
		ScriptSig: script_sig,
		Sequence:  0xffffffff,
	}

	// Add one output
	tx.TxOut = make([]*btc.TxOut, 1)
	tx.TxOut[0] = &btc.TxOut{
		Value:     0,
		Pk_script: []byte{},
	}

	checker := &script.SigChecker{
		Tx:     tx,
		Idx:    0,
		Amount: 1000,
	}

	if script.VerifyTxScript(script_pubkey, checker, 0) {
		return 1
	}

	return 0
}

// GocoinEvalScript evaluates a Bitcoin script using gocoin's script engine.
// This is exported to C/C++ and will be called by the fuzzer.
//
// Parameters:
//   - scriptData: The raw script bytes to evaluate
//   - flags: Script verification flags (like VER_P2SH, VER_WITNESS, etc.)
//   - version: Signature version (0 = base, 1 = witness v0)
//
// Returns:
//   - 1 if script evaluation succeeded
//   - 0 if script is empty
//   - 2 if script evaluation failed
//
//export GocoinEvalScript
func GocoinEvalScript(scriptData C.ByteArray, flags C.uint32_t, version C.size_t) C.int {
	// Convert C byte array to Go slice
	scriptBytes := C.GoBytes(unsafe.Pointer(scriptData.data), C.int(scriptData.length))
	if len(scriptBytes) == 0 {
		return 0
	}

	// Create a minimal dummy transaction for script evaluation context
	tx := createDummyTransaction(scriptBytes)

	// Create the SigChecker which gocoin uses for script verification
	// Based on gocoin's lib/script package
	checker := &script.SigChecker{
		Tx:     tx,
		Idx:    0,    // We're checking input 0
		Amount: 1000, // Dummy amount (needed for witness verification)
	}

	// Call gocoin's EvalScript function directly
	var stack script.ScrStack
	var execdata btc.ScriptExecutionData
	result := script.EvalScript(scriptBytes, &stack, checker, uint32(flags), script.SIGVERSION_BASE, &execdata)

	if result {
		return 1
	}
	return 2
}

// createDummyTransaction creates a minimal transaction structure
// that gocoin needs for script evaluation context.
func createDummyTransaction(pkScript []byte) *btc.Tx {
	// Create a minimal transaction with one input and one output
	tx := new(btc.Tx)
	tx.Version = 1
	tx.Lock_time = 0

	// Create dummy hash (32 bytes of zeros)
	var dummyHash [32]byte

	// Add one input (the one we're "spending" with our script)
	tx.TxIn = make([]*btc.TxIn, 1)
	tx.TxIn[0] = &btc.TxIn{
		Input: btc.TxPrevOut{
			Hash: dummyHash, // [32]byte, not Uint256
			Vout: 0,
		},
		ScriptSig: []byte{}, // Empty signature script for now
		Sequence:  0xffffffff,
	}

	// Add one output
	tx.TxOut = make([]*btc.TxOut, 1)
	tx.TxOut[0] = &btc.TxOut{
		Value:     0,
		Pk_script: []byte{},
	}

	return tx
}

// GocoinMerkleRootCompute computes the merkle root over a list of raw 32-byte
// hashes (internal byte order, concatenated) and reports whether a duplicated
// subtree (CVE-2012-2459) was detected.
//
// Input: data is n*32 bytes (n >= 1; the driver never feeds empty lists).
// Output: "<root_hex>;mutated=0|1" with the root in display byte order.
//
//export GocoinMerkleRootCompute
func GocoinMerkleRootCompute(data C.ByteArray) *C.char {
	input := C.GoBytes(unsafe.Pointer(data.data), C.int(data.length))
	if len(input) == 0 || len(input)%32 != 0 {
		return nil
	}

	// CalcMerkle appends to the slice while folding levels; hand it a copy
	// with spare capacity so the caller's buffer is never written through.
	count := len(input) / 32
	mtr := make([][32]byte, count, 3*count)
	for i := 0; i < count; i++ {
		copy(mtr[i][:], input[i*32:(i+1)*32])
	}

	root, mutated := btc.CalcMerkle(mtr)

	mutatedFlag := "0"
	if mutated {
		mutatedFlag = "1"
	}
	return C.CString(btc.NewUint256(root).String() + ";mutated=" + mutatedFlag)
}

// gocoinTruncateAfterCodesep returns the subscript starting right after the
// n-th OP_CODESEPARATOR (0 = no truncation). If the script contains fewer
// than n separators, it truncates after the last one. Mirrors pbegincodehash
// in gocoin's/Bitcoin Core's script interpreter.
func gocoinTruncateAfterCodesep(script []byte, n uint32) []byte {
	if n == 0 {
		return script
	}
	var seen uint32
	start := 0
	idx := 0
	for idx < len(script) {
		op, _, consumed, err := btc.GetOpcode(script[idx:])
		if err != nil {
			break
		}
		idx += consumed
		if op == 0xab { // OP_CODESEPARATOR
			start = idx
			seen++
			if seen == n {
				break
			}
		}
	}
	return script[start:]
}

// gocoinPushEncode returns the canonical (minimal) script push encoding of
// data, i.e. what CScript() << data produces in Bitcoin Core.
func gocoinPushEncode(data []byte) []byte {
	n := len(data)
	out := make([]byte, 0, n+5)
	switch {
	case n < 0x4c:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x4c, byte(n))
	case n <= 0xffff:
		out = append(out, 0x4d, byte(n), byte(n>>8))
	default:
		out = append(out, 0x4e, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
	}
	return append(out, data...)
}

// gocoinFindAndDelete is an exact port of Bitcoin Core's
// FindAndDelete(script, CScript() << sig). gocoin's own equivalent (delSig)
// is not exported, so the interpreter's sig-removal step is emulated here
// with Core semantics; gocoin's native delSig is therefore NOT what is being
// compared by this target.
func gocoinFindAndDelete(script, sig []byte) []byte {
	if len(sig) == 0 || len(script) == 0 {
		return script
	}
	b := gocoinPushEncode(sig)
	var result []byte
	pc, pc2, found := 0, 0, 0
	for {
		result = append(result, script[pc2:pc]...)
		for len(script)-pc >= len(b) && bytes.Equal(script[pc:pc+len(b)], b) {
			pc += len(b)
			found++
		}
		pc2 = pc
		// Advance past one opcode (Bitcoin Core CScript::GetOp semantics).
		if pc >= len(script) {
			break
		}
		_, _, consumed, err := btc.GetOpcode(script[pc:])
		if err != nil {
			break
		}
		pc += consumed
	}
	if found == 0 {
		return script
	}
	return append(result, script[pc2:]...)
}

// readVlen reads a CompactSize-style varint like gocoin's VLen, returning the
// value and the number of bytes consumed (0 on truncation).
func readVlen(b []byte, off int) (int, int) {
	if off >= len(b) {
		return 0, 0
	}
	c := b[off]
	switch {
	case c < 0xfd:
		return int(c), 1
	case c == 0xfd:
		if off+3 > len(b) {
			return 0, 0
		}
		return int(b[off+1]) | int(b[off+2])<<8, 3
	case c == 0xfe:
		if off+5 > len(b) {
			return 0, 0
		}
		return int(b[off+1]) | int(b[off+2])<<8 | int(b[off+3])<<16 | int(b[off+4])<<24, 5
	default:
		if off+9 > len(b) {
			return 0, 0
		}
		v := uint64(b[off+1]) | uint64(b[off+2])<<8 | uint64(b[off+3])<<16 | uint64(b[off+4])<<24 |
			uint64(b[off+5])<<32 | uint64(b[off+6])<<40 | uint64(b[off+7])<<48 | uint64(b[off+8])<<56
		if v > uint64(len(b)) { // guard: counts larger than the buffer can never fit
			return 0, 0
		}
		return int(v), 9
	}
}

// preflightTx walks a serialized transaction checking that every declared
// count and data length fits within the buffer. gocoin's NewTx allocates
// slices directly from untrusted CompactSize counts (make([]*TxIn, n)), so
// feeding it unvalidated bytes lets a tiny input trigger multi-GB
// allocations. Inputs failing this walk are skipped (nil) instead.
func preflightTx(b []byte) bool {
	off := 0
	need := func(n int) bool { return off+n <= len(b) }
	if !need(4) {
		return false
	}
	off += 4 // version
	segwit := false
	if need(2) && b[off] == 0 && b[off+1] == 1 {
		segwit = true
		off += 2
	}
	nIn, n := readVlen(b, off)
	if n == 0 {
		return false
	}
	off += n
	for i := 0; i < nIn; i++ {
		if !need(36) { // prevout hash + vout
			return false
		}
		off += 36
		sl, m := readVlen(b, off)
		if m == 0 {
			return false
		}
		off += m
		if !need(sl + 4) { // scriptSig + sequence
			return false
		}
		off += sl + 4
	}
	nOut, n := readVlen(b, off)
	if n == 0 {
		return false
	}
	off += n
	for i := 0; i < nOut; i++ {
		if !need(8) { // value
			return false
		}
		off += 8
		sl, m := readVlen(b, off)
		if m == 0 {
			return false
		}
		off += m
		if !need(sl) { // pk_script
			return false
		}
		off += sl
	}
	if segwit {
		for i := 0; i < nIn; i++ {
			cnt, m := readVlen(b, off)
			if m == 0 {
				return false
			}
			off += m
			for j := 0; j < cnt; j++ {
				il, k := readVlen(b, off)
				if k == 0 {
					return false
				}
				off += k
				if !need(il) {
					return false
				}
				off += il
			}
		}
	}
	return need(4) // locktime
}

// GocoinSighashCompute computes the legacy (SIGVERSION_BASE) or segwit v0
// (BIP143) signature hash for an input, emulating gocoin's interpreter:
// truncate the script after the n-th executed OP_CODESEPARATOR and, for
// legacy, remove the pushed signature being checked.
//
// Output: digest in display byte order, or nil when the input class is
// unsupported (tx parse failure or no inputs).
//
//export GocoinSighashCompute
func GocoinSighashCompute(txData C.ByteArray, scriptData C.ByteArray, sigData C.ByteArray, inputIndex C.uint32_t, nCodesep C.uint32_t, amount C.uint64_t, sighashType C.uint32_t, isV0 C.int) (res *C.char) {
	// gocoin can panic on malformed structures; treat a panic as "unsupported
	// input" so the driver simply skips this module.
	defer func() {
		if r := recover(); r != nil {
			res = nil
		}
	}()

	txBytes := C.GoBytes(unsafe.Pointer(txData.data), C.int(txData.length))
	if !preflightTx(txBytes) {
		return nil
	}
	tx, _ := btc.NewTx(txBytes)
	if tx == nil || len(tx.TxIn) == 0 {
		return nil
	}
	// WitnessSigHash uses the cached-hash fields in the embedded TxVerVars,
	// which NewTx leaves unallocated.
	tx.AllocVerVars()
	idx := int(uint32(inputIndex) % uint32(len(tx.TxIn)))

	script := C.GoBytes(unsafe.Pointer(scriptData.data), C.int(scriptData.length))
	sig := C.GoBytes(unsafe.Pointer(sigData.data), C.int(sigData.length))

	script = gocoinTruncateAfterCodesep(script, uint32(nCodesep))

	var digest []byte
	if isV0 == 0 {
		script = gocoinFindAndDelete(script, sig)
		digest = tx.SignatureHash(script, idx, int32(sighashType))
	} else {
		digest = tx.WitnessSigHash(script, uint64(amount), idx, int32(sighashType))
	}
	if len(digest) != 32 {
		return nil
	}

	// Digest is in internal byte order; display it reversed like
	// uint256::ToString / Uint256.String.
	return C.CString(btc.NewUint256(digest).String())
}

// GocoinFreeString frees a C string that was allocated by Go.
// Must be called to prevent memory leaks.
//
//export GocoinFreeString
func GocoinFreeString(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

// main is required for cgo but does nothing
func main() {}
