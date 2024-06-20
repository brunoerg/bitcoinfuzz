package main

import "C"
import (
	"bytes"
	"unsafe"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

//export go_btcd_des_block
func go_btcd_des_block(cinput *C.uchar, len C.int) *C.char {

	data := C.GoBytes(unsafe.Pointer(cinput), len)

	b, err := btcutil.NewBlockFromBytes(data)
	if err == nil {
		return C.CString(b.Hash().String())
	}

	return C.CString("")
}

//export go_btcd_des_tx
func go_btcd_des_tx(cinput *C.uchar, len C.int) *C.char {
	data := C.GoBytes(unsafe.Pointer(cinput), len)

	b, err := btcutil.NewTxFromBytes(data)
	if err == nil {
		err := blockchain.CheckTransactionSanity(b)
		if err == nil {
			return C.CString(b.Hash().String())
		}
	}

	return C.CString("")
}

//export go_btcd_bech32
func go_btcd_bech32(cinput *C.uchar, len C.int) *C.char {
	data := C.GoBytes(unsafe.Pointer(cinput), len)
	data_str := string(data)
	s, _, err := bech32.Decode(data_str)

	if err == nil {
		return C.CString(s)
	}

	return C.CString("")
}

//export go_btcd_psbt
func go_btcd_psbt(cinput *C.uchar, len C.int) *C.char {
	data := C.GoBytes(unsafe.Pointer(cinput), len)

	if _, err := psbt.NewFromRawBytes(bytes.NewReader(data), false); err == nil {
		return C.CString("1")
	}

	return C.CString("0")
}

func main() {

}
