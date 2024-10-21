package main

import "C"
import (
	"bytes"
	"unsafe"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/wire"
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

//export go_btcd_addrv2
func go_btcd_addrv2(cinput *C.uchar, datalen C.int, count *C.ulonglong) bool {
	data := C.GoBytes(unsafe.Pointer(cinput), datalen)
	r := bytes.NewReader(data)
	m := &wire.MsgAddrV2{}
	err := m.BtcDecode(r, 0, wire.WitnessEncoding)

	actual_count := 0
	for i := 0; i < len(m.AddrList); i++ {
		if m.AddrList[i].Addr != nil {
			actual_count++
		}
	}
	*count = C.ulonglong(actual_count)

	return err == nil
}

//export go_btcd_rawmessage
func go_btcd_rawmessage(cinput *C.uchar, datalen C.int) C.int {
	data := C.GoBytes(unsafe.Pointer(cinput), datalen)
	r := bytes.NewReader(data)

	_, _, err := wire.ReadMessage(r, wire.ProtocolVersion, wire.MainNet)

	if err == nil {
		return 0
	}

	return -1
}

func main() {

}
