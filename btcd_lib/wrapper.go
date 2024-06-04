package main

import "C"
import (
	"unsafe"

	"github.com/btcsuite/btcd/btcutil"
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

func main() {

}
