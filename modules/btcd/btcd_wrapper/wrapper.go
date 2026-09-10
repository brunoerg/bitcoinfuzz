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
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"encoding/hex"

	btcdaddress "github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ellswift"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

//export BTCDVerifyScript
func BTCDVerifyScript(scriptSig C.ByteArray, scriptPubKey C.ByteArray) C.int {
	script_sig := C.GoBytes(unsafe.Pointer(scriptSig.data), C.int(scriptSig.length))
	if len(script_sig) == 0 {
		return 0
	}

	script_pubkey := C.GoBytes(unsafe.Pointer(scriptPubKey.data), C.int(scriptPubKey.length))
	if len(script_pubkey) == 0 {
		return 0
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	txIn := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
	txIn.SignatureScript = script_sig
	tx.AddTxIn(txIn)

	prevoutAmt := int64(1000)
	fetcher := txscript.NewCannedPrevOutputFetcher(script_pubkey, prevoutAmt)
	vm, err := txscript.NewEngine(
		script_pubkey,
		tx,
		0,   // input index
		0,   // flags
		nil, // sigCache
		nil, // hashCache (TxSigHashes)
		prevoutAmt,
		fetcher,
	)

	if err != nil {
		return 2
	}

	if err := vm.Execute(); err != nil {
		return 2
	}

	return 1
}

//export BTCDParseP2PMessage
func BTCDParseP2PMessage(messageData C.ByteArray) *C.char {
	data := C.GoBytes(unsafe.Pointer(messageData.data), messageData.length)
	reader := bytes.NewReader(data)

	_, msg, _, err := wire.ReadMessageN(reader, 70016, wire.MainNet)
	if err != nil {
		return C.CString("0")
	}

	return C.CString(msg.Command())
}

// getAddrBytes extracts raw address bytes from a net.Addr using reflection
// since btcd's address types are unexported
func getAddrBytes(addr net.Addr) []byte {
	v := reflect.ValueOf(addr)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	addrField := v.FieldByName("addr")
	if !addrField.IsValid() {
		return nil
	}
	// Get the underlying bytes from the array
	length := addrField.Len()
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = byte(addrField.Index(i).Uint())
	}
	return result
}

// getAddrType determines the address type from a net.Addr using reflection
// to inspect the underlying type name since btcd's address types are unexported
func getAddrType(addr net.Addr) string {
	typeName := reflect.TypeOf(addr).String()
	switch {
	case strings.Contains(typeName, "ipv4Addr"):
		return "ipv4"
	case strings.Contains(typeName, "ipv6Addr"):
		return "ipv6"
	case strings.Contains(typeName, "torv3Addr"):
		return "tor"
	case strings.Contains(typeName, "torv2Addr"):
		return "torv2"
	case strings.Contains(typeName, "i2pAddr"):
		return "i2p"
	case strings.Contains(typeName, "cjdnsAddr"):
		return "cjdns"
	default:
		return ""
	}
}

//export BTCDAddrv2
func BTCDAddrv2(addrv2Data C.ByteArray) *C.char {
	data := C.GoBytes(unsafe.Pointer(addrv2Data.data), addrv2Data.length)
	r := bytes.NewReader(data)
	m := &wire.MsgAddrV2{}
	err := m.BtcDecode(r, 0, wire.WitnessEncoding)
	if err != nil {
		// BTCD parses TorV2, so it may return an error for an invalid address size
		// of a TorV2, which other implementations would not throw.
		if err == wire.ErrInvalidAddressSize {
			return nil
		}
		return C.CString("[]")
	}

	// IPv4-mapped IPv6 prefix (::ffff:0:0/96) - RFC 4291
	ipv4MappedPrefix := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF}

	var entries []string
	for i := 0; i < len(m.AddrList); i++ {
		if m.AddrList[i].Addr != nil {
			addr := m.AddrList[i].Addr
			addrBytes := getAddrBytes(addr)
			if addrBytes == nil {
				continue
			}
			addrHex := hex.EncodeToString(addrBytes)
			addrType := getAddrType(addr)
			if !addrmgr.IsRoutable(m.AddrList[i]) {
				continue
			}
			if addrType == "torv2" {
				continue
			}

			// These verification should be in BTCD library.
			if addrType == "ipv6" {
				// Skip IPv4-mapped IPv6 addresses (RFC 4291)
				// These should use network ID 0x01 (IPv4), not 0x02 (IPv6)
				if len(addrBytes) >= 12 && bytes.HasPrefix(addrBytes, ipv4MappedPrefix) {
					continue
				}

				// RFC 7343 - ORCHIDv2 - 2001:20::/28
				if addrBytes[0] == 0x20 && addrBytes[1] == 0x01 &&
					addrBytes[2] == 0x00 && (addrBytes[3]&0xf0) == 0x20 {
					continue
				}
			}

			time := m.AddrList[i].Timestamp.Unix()
			services := m.AddrList[i].Services
			port := m.AddrList[i].Port

			entry := fmt.Sprintf("{\"addr\":\"%s\",\"type\":\"%s\",\"time\":\"%d\",\"services\":\"%d\",\"port\":\"%d\"}",
				addrHex, addrType, time, services, port)
			entries = append(entries, entry)
		}
	}

	return C.CString("[" + strings.Join(entries, ",") + "]")
}

//export BTCDScriptAsm
func BTCDScriptAsm(scriptData C.ByteArray) *C.char {
	script := C.GoBytes(unsafe.Pointer(scriptData.data), scriptData.length)
	disasm, err := txscript.DisasmString(script)
	if err != nil {
		return C.CString("")
	}
	return C.CString(disasm)
}

//export BTCDDesBlock
func BTCDDesBlock(scriptData C.ByteArray) *C.char {
	buffer := C.GoBytes(unsafe.Pointer(scriptData.data), scriptData.length)

	block, err := btcutil.NewBlockFromBytes(buffer)
	if err != nil {
		return C.CString("0")
	}

	// Easiest possible PoW
	powLimit := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	err = blockchain.CheckBlockSanity(block, powLimit, blockchain.NewMedianTime())
	if err != nil {
		return C.CString("0")
	}

	err = blockchain.ValidateWitnessCommitment(block)
	if err != nil {
		return C.CString("0")
	}

	return C.CString(block.Hash().String())
}

//export BTCDFreeString
func BTCDFreeString(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

// BTCDMerkleRootCompute computes the merkle root over a list of raw 32-byte
// hashes (internal byte order, concatenated) and reports whether a duplicated
// subtree (CVE-2012-2459) was detected.
//
// btcd's exported merkle entry points (CalcMerkleRoot, BuildMerkleTreeStore)
// operate on []*btcutil.Tx rather than raw hashes, so the tree reduction
// below mirrors Bitcoin Core's ComputeMerkleRoot (duplicate the last hash on
// odd levels, hash pairs left to right) while the consensus-critical pair
// hashing itself is btcd's exported HashMerkleBranches (double SHA256 of the
// concatenated branches).
//
// Input: data is n*32 bytes (n >= 1; the driver never feeds empty lists).
// Output: "<root_hex>;mutated=0|1" with the root in display byte order.
//
//export BTCDMerkleRootCompute
func BTCDMerkleRootCompute(data C.ByteArray) *C.char {
	input := C.GoBytes(unsafe.Pointer(data.data), C.int(data.length))
	if len(input) == 0 || len(input)%32 != 0 {
		return nil
	}

	count := len(input) / 32
	hashes := make([]chainhash.Hash, count)
	for i := 0; i < count; i++ {
		copy(hashes[i][:], input[i*32:(i+1)*32])
	}

	mutated := false
	for len(hashes) > 1 {
		// Detect duplicated subtrees (CVE-2012-2459): any two consecutive
		// hashes at even offsets before the odd-level duplication.
		for pos := 0; pos+1 < len(hashes); pos += 2 {
			if hashes[pos] == hashes[pos+1] {
				mutated = true
			}
		}
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		next := make([]chainhash.Hash, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			next[i/2] = blockchain.HashMerkleBranches(&hashes[i], &hashes[i+1])
		}
		hashes = next
	}

	mutatedFlag := "0"
	if mutated {
		mutatedFlag = "1"
	}
	return C.CString(hashes[0].String() + ";mutated=" + mutatedFlag)
}

// truncateAfterCodesep returns the subscript starting right after the n-th
// OP_CODESEPARATOR (0 = no truncation). If the script contains fewer than n
// separators, it truncates after the last one. Mirrors pbegincodehash in
// Bitcoin Core's EvalScript.
func truncateAfterCodesep(script []byte, n uint32) []byte {
	if n == 0 {
		return script
	}
	var seen uint32
	start := 0
	tokenizer := txscript.MakeScriptTokenizer(0, script)
	for tokenizer.Next() {
		if tokenizer.Opcode() == 0xab { // OP_CODESEPARATOR
			// ByteIndex points just past the parsed opcode.
			start = int(tokenizer.ByteIndex())
			seen++
			if seen == n {
				break
			}
		}
	}
	return script[start:]
}

// pushEncode returns the canonical (minimal) script push encoding of data,
// i.e. what CScript() << data produces in Bitcoin Core.
func pushEncode(data []byte) []byte {
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

// nextOpOffset returns the offset just past the opcode starting at pc,
// following Bitcoin Core's CScript::GetOp push parsing. The second return
// value reports whether the opcode parsed cleanly.
func nextOpOffset(script []byte, pc int) (int, bool) {
	if pc >= len(script) {
		return pc, false
	}
	opcode := script[pc]
	i := pc + 1
	if opcode <= 0x4e { // pushdata family
		var nSize int
		switch {
		case opcode < 0x4c:
			nSize = int(opcode)
		case opcode == 0x4c:
			if len(script)-i < 1 {
				return i, false
			}
			nSize = int(script[i])
			i++
		case opcode == 0x4d:
			if len(script)-i < 2 {
				return i, false
			}
			nSize = int(script[i]) | int(script[i+1])<<8
			i += 2
		default: // 0x4e
			if len(script)-i < 4 {
				return i, false
			}
			nSize = int(script[i]) | int(script[i+1])<<8 | int(script[i+2])<<16 | int(script[i+3])<<24
			i += 4
		}
		if len(script)-i < nSize {
			return i, false
		}
		i += nSize
	}
	return i, true
}

// findAndDelete is an exact port of Bitcoin Core's FindAndDelete(script, CScript() << sig):
// it walks the script opcode by opcode and removes every occurrence of the
// canonical push encoding of sig, including matches starting mid-opcode after
// a previous deletion.
func findAndDelete(script, sig []byte) []byte {
	if len(sig) == 0 || len(script) == 0 {
		return script
	}
	b := pushEncode(sig)
	var result []byte
	pc, pc2, found := 0, 0, 0
	for {
		result = append(result, script[pc2:pc]...)
		for len(script)-pc >= len(b) && bytes.Equal(script[pc:pc+len(b)], b) {
			pc += len(b)
			found++
		}
		pc2 = pc
		next, ok := nextOpOffset(script, pc)
		if !ok {
			break
		}
		pc = next
	}
	if found == 0 {
		return script
	}
	return append(result, script[pc2:]...)
}

// BTCDSighashCompute computes the legacy (SigVersion::BASE) or segwit v0
// (BIP143) signature hash for an input, emulating btcd's interpreter:
// truncate the script after the n-th executed OP_CODESEPARATOR and, for
// legacy, remove the pushed signature being checked.
//
// Input: txData is a serialized transaction; script the scriptCode with
// code separators intact; sigData the signature blob to delete (legacy only).
// Output: digest in display byte order, or nil when the input class is
// unsupported (tx parse failure, no inputs, or btcd's exported sighash API
// rejecting an unparseable script — the driver compares other modules then).
//
//export BTCDSighashCompute
func BTCDSighashCompute(txData C.ByteArray, scriptData C.ByteArray, sigData C.ByteArray, inputIndex C.uint32_t, nCodesep C.uint32_t, amount C.uint64_t, sighashType C.uint32_t, isV0 C.int) *C.char {
	txBytes := C.GoBytes(unsafe.Pointer(txData.data), C.int(txData.length))
	tx, err := btcutil.NewTxFromBytes(txBytes)
	if err != nil {
		return nil
	}
	msgTx := tx.MsgTx()
	if len(msgTx.TxIn) == 0 {
		return nil
	}
	idx := int(uint32(inputIndex) % uint32(len(msgTx.TxIn)))

	script := C.GoBytes(unsafe.Pointer(scriptData.data), C.int(scriptData.length))
	sig := C.GoBytes(unsafe.Pointer(sigData.data), C.int(sigData.length))

	script = truncateAfterCodesep(script, uint32(nCodesep))

	var digest []byte
	if isV0 == 0 {
		script = findAndDelete(script, sig)
		digest, err = txscript.CalcSignatureHash(script, txscript.SigHashType(sighashType), msgTx, idx)
	} else {
		// PrevOutputFetcher is only needed for taproot (v1) sighashes; a
		// canned non-taproot output keeps the v0 midstates tx-local.
		fetcher := txscript.NewCannedPrevOutputFetcher(nil, 0)
		sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)
		digest, err = txscript.CalcWitnessSigHash(script, sigHashes, txscript.SigHashType(sighashType), msgTx, idx, int64(amount))
	}
	if err != nil || len(digest) != 32 {
		return nil
	}

	// Digest is in internal byte order; display it reversed like
	// uint256::ToString / chainhash.Hash.String.
	var h chainhash.Hash
	copy(h[:], digest)
	return C.CString(h.String())
}

//export BTCDTransactionEval
func BTCDTransactionEval(data C.ByteArray) *C.char {
	buffer := C.GoBytes(unsafe.Pointer(data.data), data.length)
	tx, err := btcutil.NewTxFromBytes(buffer)
	if err != nil {
		return C.CString("0")
	}

	err_sanity := blockchain.CheckTransactionSanity(tx)
	if err_sanity != nil {
		return C.CString("0")
	}

	res := tx.WitnessHash().String()
	res += strconv.Itoa(tx.MsgTx().SerializeSize())
	return C.CString(res)
}

// finalWitnessHasItems reports whether a PSBT_IN_FINAL_SCRIPTWITNESS value
// holds at least one witness item. btcd keeps this field as the raw serialized
// witness (a compact-size item count followed by the items), so an *empty*
// stack is still one byte (0x00) and a plain len() > 0 check would call it
// finalized. Bitcoin Core stores its final witness as a plain CScriptWitness
// whose IsNull() is just stack.empty(), so it cannot distinguish an absent key
// from one present with a zero-item stack; matching on item count keeps the
// `finalized` flag comparable across modules. An empty witness finalizes nothing.
func finalWitnessHasItems(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	count, err := wire.ReadVarInt(bytes.NewReader(raw), 0)
	if err != nil {
		return false
	}
	return count > 0
}

//export BTCDParsePSBT
func BTCDParsePSBT(data C.ByteArray) *C.char {
	buffer := C.GoBytes(unsafe.Pointer(data.data), data.length)

	var packet *psbt.Packet
	var err error

	reader := bytes.NewReader(buffer)
	packet, err = psbt.NewFromRawBytes(reader, false)

	if err != nil { // base64 if binary fails
		str := string(buffer)
		decodedBytes, decodeErr := base64.StdEncoding.DecodeString(str)
		if decodeErr != nil {
			return C.CString("INVALID")
		}
		reader = bytes.NewReader(decodedBytes)
		packet, err = psbt.NewFromRawBytes(reader, false)
		if err != nil {
			return C.CString("INVALID")
		}
	}

	// Bitcoin Core rejects extra data after a complete PSBT, while btcd stops
	// after reading the expected maps. Require the entire input to be consumed.
	if reader.Len() != 0 {
		return C.CString("INVALID")
	}
	var result strings.Builder // format psbt similar to rust_bitcoin

	//result.WriteString(fmt.Sprintf("v=%d;", packet.UnsignedTx.Version))        // add Tx ver
	result.WriteString(fmt.Sprintf("lock_time=%d;", packet.UnsignedTx.LockTime)) // add locktime
	result.WriteString(fmt.Sprintf("inputs=%d;", len(packet.UnsignedTx.TxIn)))   // add ip count
	result.WriteString(fmt.Sprintf("outputs=%d;", len(packet.UnsignedTx.TxOut))) // add op count

	// processing ip
	for i, txIn := range packet.UnsignedTx.TxIn {
		if i < len(packet.Inputs) {
			// prev op (txid:vout)
			result.WriteString(fmt.Sprintf("input%dprevious_output=%s:%d;",
				i, txIn.PreviousOutPoint.Hash.String(), txIn.PreviousOutPoint.Index))

			// seq number
			result.WriteString(fmt.Sprintf("input%dsequence=%d;", i, txIn.Sequence))

			// check UTXO info
			if packet.Inputs[i].WitnessUtxo != nil || packet.Inputs[i].NonWitnessUtxo != nil {
				result.WriteString(fmt.Sprintf("input%dutxo=1;", i))
			}

			// count partial sig
			partialSignatureCount := len(packet.Inputs[i].PartialSigs)
			result.WriteString(fmt.Sprintf("input%dpartial_signatures=%d;", i, partialSignatureCount))

			// redeem/witness scripts as hex (empty if absent)
			result.WriteString(fmt.Sprintf("input%dredeem_script=%x;", i, packet.Inputs[i].RedeemScript))
			result.WriteString(fmt.Sprintf("input%dwitness_script=%x;", i, packet.Inputs[i].WitnessScript))

			// sighash type (0 if unset)
			result.WriteString(fmt.Sprintf("input%dsighash_type=%d;", i, uint32(packet.Inputs[i].SighashType)))

			// BIP32 derivation count
			result.WriteString(fmt.Sprintf("input%dbip32=%d;", i, len(packet.Inputs[i].Bip32Derivation)))

			// finalized status
			if len(packet.Inputs[i].FinalScriptSig) > 0 || finalWitnessHasItems(packet.Inputs[i].FinalScriptWitness) {
				result.WriteString(fmt.Sprintf("input%dfinalized=1;", i))
			}
		}
	}

	// processing op
	for i, txOut := range packet.UnsignedTx.TxOut {
		if i < len(packet.Outputs) {
			result.WriteString(fmt.Sprintf("output%dval=%d;", i, txOut.Value))
			scriptHex := fmt.Sprintf("%x", txOut.PkScript) // script pubkey as hex
			result.WriteString(fmt.Sprintf("output%dscript=%s;", i, scriptHex))

			// redeem/witness scripts as hex (empty if absent)
			result.WriteString(fmt.Sprintf("output%dredeem_script=%x;", i, packet.Outputs[i].RedeemScript))
			result.WriteString(fmt.Sprintf("output%dwitness_script=%x;", i, packet.Outputs[i].WitnessScript))

			// BIP32 derivation count
			result.WriteString(fmt.Sprintf("output%dbip32=%d;", i, len(packet.Outputs[i].Bip32Derivation)))
		}
	}

	return C.CString(result.String())
}

//export BTCDAddress
func BTCDAddress(data C.ByteArray) *C.char {
	addrBytes := C.GoBytes(unsafe.Pointer(data.data), data.length)
	addrStr := string(addrBytes)

	addr, err := btcdaddress.DecodeAddress(addrStr, &chaincfg.MainNetParams)
	if err != nil {
		return C.CString("INVALID")
	}

	var prefix string
	switch addr.(type) {
	case *btcdaddress.AddressPubKeyHash:
		prefix = "PKH:"
	case *btcdaddress.AddressScriptHash:
		prefix = "SH:"
	case *btcdaddress.AddressWitnessPubKeyHash:
		prefix = "WPKH:"
	case *btcdaddress.AddressWitnessScriptHash:
		prefix = "WSH:"
	case *btcdaddress.AddressTaproot:
		prefix = "TR:"
	default:
		prefix = "UNK:"
	}

	return C.CString(prefix + addr.EncodeAddress())
}

//export BTCDBip32MasterKeygen
func BTCDBip32MasterKeygen(data C.ByteArray) *C.char {
	seed := C.GoBytes(unsafe.Pointer(data.data), data.length)
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		// Skip seed length validation errors (128-512 bits requirement) as other
		// implementations don't enforce this constraint.
		if err.Error() == "seed length must be between 128 and 512 bits" {
			return nil
		}
		return C.CString("")
	}
	return C.CString(masterKey.String())
}

//export BTCDSignSchnorr
func BTCDSignSchnorr(privKey C.ByteArray, hash C.ByteArray, aux C.ByteArray) *C.char {
	privKeyBytes := C.GoBytes(unsafe.Pointer(privKey.data), privKey.length)
	hashBytes := C.GoBytes(unsafe.Pointer(hash.data), hash.length)
	auxBytes := C.GoBytes(unsafe.Pointer(aux.data), aux.length)

	// Ensure we have exactly 32 bytes for the aux data
	var auxArray [32]byte
	copy(auxArray[:], auxBytes)

	priv, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Use CustomNonce to force determinism with the provided aux data
	sig, err := schnorr.Sign(priv, hashBytes, schnorr.CustomNonce(auxArray))
	if err != nil {
		return C.CString("")
	}

	return C.CString(hex.EncodeToString(sig.Serialize()))
}

//export BTCDDecodeEllswift
func BTCDDecodeEllswift(buffer C.ByteArray) *C.char {
	ell64 := C.GoBytes(unsafe.Pointer(buffer.data), buffer.length)
	u := new(btcec.FieldVal)
	t := new(btcec.FieldVal)
	u.SetBytes((*[32]byte)(ell64[0:32]))
	t.SetBytes((*[32]byte)(ell64[32:64]))

	tIsOdd := t.Normalize().IsOdd()

	x, err := ellswift.XSwiftEC(u, t)
	if err != nil {
		panic(fmt.Sprintf("XSwiftEC failed unexpectedly: %v", err))
	}

	ySqr := new(btcec.FieldVal).SquareVal(x).Mul(x).AddInt(7)
	y := new(btcec.FieldVal)
	if !y.SquareRootVal(ySqr) {
		panic("SquareRootVal failed: x from XSwiftEC should always be on curve")
	}

	// y parity should match original t parity
	if y.IsOdd() != tIsOdd {
		y.Negate(1).Normalize()
	}
	pubkey := btcec.NewPublicKey(x, y)

	return C.CString(hex.EncodeToString(pubkey.SerializeCompressed()))
}

//export BTCDRoundtripEllswift
func BTCDRoundtripEllswift(buffer C.ByteArray) *C.char {
	privKeyBytes := C.GoBytes(unsafe.Pointer(buffer.data), buffer.length)

	// Match secp256k1_ec_seckey_verify: reject 0 and values >= curve order.
	keyInt := new(big.Int).SetBytes(privKeyBytes)
	if keyInt.Sign() == 0 || keyInt.Cmp(btcec.S256().N) >= 0 {
		return nil
	}

	_, pub := btcec.PrivKeyFromBytes(privKeyBytes)

	compressed := pub.SerializeCompressed()
	var xBytes [32]byte
	copy(xBytes[:], compressed[1:33])

	x := new(btcec.FieldVal)
	x.SetBytes(&xBytes)

	u, t, err := ellswift.XElligatorSwift(x)
	if err != nil {
		return C.CString("")
	}

	// XElligatorSwift takes only x, so the resulting t's parity is arbitrary.
	// BIP324 derives the decoded y's parity from t, so force t's parity to
	// match the original y. XSwiftEC is even in t, so negating preserves x.
	yIsOdd := compressed[0] == 0x03
	if t.Normalize().IsOdd() != yIsOdd {
		t.Negate(1).Normalize()
	}

	tIsOdd := t.Normalize().IsOdd()

	decodedX, err := ellswift.XSwiftEC(u, t)
	if err != nil {
		panic(fmt.Sprintf("XSwiftEC failed unexpectedly: %v", err))
	}

	ySqr := new(btcec.FieldVal).SquareVal(decodedX).Mul(decodedX).AddInt(7)
	y := new(btcec.FieldVal)
	if !y.SquareRootVal(ySqr) {
		panic("SquareRootVal failed: x from XElligatorSwift should always be on curve")
	}

	if y.IsOdd() != tIsOdd {
		y.Negate(1).Normalize()
	}
	pubkey := btcec.NewPublicKey(decodedX, y)

	return C.CString(hex.EncodeToString(pubkey.SerializeCompressed()))
}

//export BTCDSchnorrVerify
func BTCDSchnorrVerify(buffer C.ByteArray, hash C.ByteArray, sig C.ByteArray) *C.char {
	privkeyBytes := C.GoBytes(unsafe.Pointer(buffer.data), buffer.length)
	hashBytes := C.GoBytes(unsafe.Pointer(hash.data), hash.length)
	sigBytes := C.GoBytes(unsafe.Pointer(sig.data), sig.length)

	_, pubkey := btcec.PrivKeyFromBytes(privkeyBytes)

	signature, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return C.CString("INVALID")
	}

	if !signature.Verify(hashBytes, pubkey) {
		return C.CString("INVALID")
	}
	return C.CString("VALID")
}

//export BTCDBip32DeserializeExtendedKey
func BTCDBip32DeserializeExtendedKey(data C.ByteArray) *C.char {
	b := C.GoBytes(unsafe.Pointer(data.data), data.length)
	s := string(b)

	key, err := hdkeychain.NewKeyFromString(s)
	if err != nil {
		return C.CString("INVALID")
	}

	depth := key.Depth()
	fp := key.ParentFingerprint()
	child := key.ChildIndex()
	chaincode := key.ChainCode()

	var keyBytes []byte
	// hdkeychain unexports its fields, ECPrivKey/ECPubKey are the only way to access raw key bytes from outside the package
	if key.IsPrivate() {
		priv, err := key.ECPrivKey()
		if err != nil {
			return C.CString("INVALID")
		}
		keyBytes = priv.Serialize()
	} else {
		pub, err := key.ECPubKey()
		if err != nil {
			return C.CString("INVALID")
		}
		keyBytes = pub.SerializeCompressed()
	}

	res := fmt.Sprintf(
		"depth=%02x;fp=%08x;child=%08x;chaincode=%x;key=%x",
		depth,
		fp,
		child,
		chaincode,
		keyBytes,
	)

	return C.CString(res)
}

func main() {}
