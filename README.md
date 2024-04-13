# bitcoinfuzz

Differential Fuzzing of Bitcoin implementations and libraries.
It currently support `Bitcoin Core`, `rust-bitcoin` and `rust-miniscript`.
Note this project is a WIP and might be not stable.

# Build

`cd rust_bitcoin_lib && cargo build --release && cd .. && make`

# Running

`FUZZ=target_name ./bitcoinfuzz`


-------------------------------------------
### Bugs/inconsistences found by Bitcoinfuzz

- sipa/miniscript: https://github.com/sipa/miniscript/issues/140
- rust-miniscript: https://github.com/rust-bitcoin/rust-miniscript/issues/633
