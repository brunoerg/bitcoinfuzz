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
	"encoding/binary"
	"encoding/hex"
	"unsafe"

	"github.com/utreexo/utreexo"
)

//export UtreexoStumpUpdate
func UtreexoStumpUpdate(newTxouts C.ByteArray) *C.char {
	count := int(newTxouts.length) / 32

	addHashes := make([]utreexo.Hash, count)
	if count > 0 {
		hashBytes := unsafe.Slice((*byte)(unsafe.Pointer(newTxouts.data)), newTxouts.length)
		for i := range count {
			var h utreexo.Hash
			copy(h[:], hashBytes[i*32:(i+1)*32])
			addHashes[i] = h
		}
	}

	var stump utreexo.Stump
	_, err := stump.Update([]utreexo.Hash{}, addHashes, utreexo.Proof{})
	if err != nil {
		return C.CString("")
	}

	// Serialize the Stump into a hex string.
	//
	// NOTE: since `utreexo` does not implement `Stump.serialize`,
	// we just serialize this exactly like `rustreexo`.
	var stumpSer []byte

	leaves := make([]byte, 8)
	binary.LittleEndian.PutUint64(leaves, stump.NumLeaves)
	stumpSer = append(stumpSer, leaves...)
	rootCount := make([]byte, 8)
	binary.LittleEndian.PutUint64(rootCount, uint64(len(stump.Roots)))
	stumpSer = append(stumpSer, rootCount...)
	for _, root := range stump.Roots {
		stumpSer = append(stumpSer, 0x02)
		stumpSer = append(stumpSer, root[:]...)
	}

	return C.CString(hex.EncodeToString(stumpSer))
}

func byteArrayToHashes(arr C.ByteArray) []utreexo.Hash {
	count := int(arr.length) / 32
	hashes := make([]utreexo.Hash, count)
	if count > 0 {
		raw := unsafe.Slice((*byte)(unsafe.Pointer(arr.data)), arr.length)
		for i := range count {
			copy(hashes[i][:], raw[i*32:(i+1)*32])
		}
	}
	return hashes
}

// serializeTaggedRoots mimics rustreexo's `BitcoinNodeHash` serialization:
// empty roots are a single 0x00 byte, present roots are 0x02 followed by the
// 32-byte hash.
func serializeTaggedRoots(roots []utreexo.Hash) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, uint64(len(roots)))
	for _, root := range roots {
		if root == (utreexo.Hash{}) {
			out = append(out, 0x00)
		} else {
			out = append(out, 0x02)
			out = append(out, root[:]...)
		}
	}
	return out
}

//export UtreexoStumpUpdateWithDels
func UtreexoStumpUpdateWithDels(addHashes, delHashes, newAddHashes C.ByteArray) *C.char {
	adds := byteArrayToHashes(addHashes)
	dels := byteArrayToHashes(delHashes)
	newAdds := byteArrayToHashes(newAddHashes)

	// Build the full accumulator over the first batch so it can prove the
	// deletions.
	pollard := utreexo.NewAccumulator()
	leaves := make([]utreexo.Leaf, len(adds))
	for i, hash := range adds {
		leaves[i] = utreexo.Leaf{Hash: hash, Remember: true}
	}
	if err := pollard.Modify(leaves, nil, utreexo.Proof{}); err != nil {
		return C.CString("")
	}

	// Track the same state in a Stump (the compact-state client).
	var stump utreexo.Stump
	if _, err := stump.Update(nil, adds, utreexo.Proof{}); err != nil {
		return C.CString("")
	}

	proof, err := pollard.Prove(dels)
	if err != nil {
		return C.CString("")
	}

	// The second update deletes the proven leaves and adds the new batch,
	// like a block spending and creating UTXOs.
	if _, err := stump.Update(dels, newAdds, proof); err != nil {
		return C.CString("")
	}
	newLeaves := make([]utreexo.Leaf, len(newAdds))
	for i, hash := range newAdds {
		newLeaves[i] = utreexo.Leaf{Hash: hash, Remember: true}
	}
	if err := pollard.Modify(newLeaves, dels, proof); err != nil {
		return C.CString("")
	}

	// Serialize the Stump like `rustreexo` does, then append the full
	// accumulator's roots so both states get compared across modules.
	var out []byte
	numLeaves := make([]byte, 8)
	binary.LittleEndian.PutUint64(numLeaves, stump.NumLeaves)
	out = append(out, numLeaves...)
	out = append(out, serializeTaggedRoots(stump.Roots)...)

	response := hex.EncodeToString(out) + ":" +
		hex.EncodeToString(serializeTaggedRoots(pollard.GetRoots()))
	return C.CString(response)
}

//export UtreexoVerify
func UtreexoVerify(buffer *C.char) *C.char {
	panic("unimplemented")
}

func main() {}
