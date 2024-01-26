# bitcoinfuzz

Differential Fuzzing of Bitcoin implementations and libraries.

This project is experimental and will change frequently. It's not stable.

# Build

`cd rust_bitcoin_lib && cargo build --release && cd .. && make`

# Running

`FUZZ=target_name ./bitcoinfuzz`


-------------------------------------------
### Bugs/inconsistences/interesting stuff found by Bitcoinfuzz

- sipa/miniscript: https://github.com/sipa/miniscript/issues/140
- rust-miniscript: https://github.com/rust-bitcoin/rust-miniscript/issues/633
