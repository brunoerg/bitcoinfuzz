module main

go 1.21.6

require (
	github.com/btcsuite/btcd v0.23.5-0.20231219003633-4c2ce6daed8f // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.1.3 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/btcutil/psbt v1.1.9 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
)

replace github.com/btcsuite/btcd => ../dependencies/btcd/
