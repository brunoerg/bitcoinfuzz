# bitcoinfuzz

Differential Fuzzing of Bitcoin implementations and libraries. At the current state, the goal is fuzzing miniscript implementations.

This project is experimental and will change frequently. It's not stable.

# Build

`cd rust_bitcoin_lib && cargo build --release && cd .. && make`

# Running

`FUZZ=miniscript_string ./bitcoinfuzz`
