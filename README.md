# bitcoinfuzz

Differential Fuzzing of Bitcoin implementations and libraries.
It currently supports `Bitcoin Core`, `btcd`, `rust-bitcoin` and `rust-miniscript`.
Note this project is a WIP and might be not stable.

# Installation

First clone the repo and open it using:

```bash
git clone --recursive https://github.com/brunoerg/bitcoinfuzz && cd bitcoinfuzz
```

Next update the submodules:

```bash
git submodule update
```

Now, you can build the project by running:

```bash
make
```

It is also possible to target a specific commit or tag of the dependencies during compilation:

```bash
make BTCD=v0.24.0 RUST_BITCOIN=aedb097
```

Once the compilation is complete bitcoinfuzz can be executed by:

```bash
FUZZ=target_name ./bitcoinfuzz
```

-------------------------------------------
### Bugs/inconsistences/mismatches found by Bitcoinfuzz

- sipa/miniscript: https://github.com/sipa/miniscript/issues/140
- rust-miniscript: https://github.com/rust-bitcoin/rust-miniscript/issues/633
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/2681
- btcd: https://github.com/btcsuite/btcd/issues/2195 (API mismatch with Bitcoin Core)
- Bitcoin Core: https://github.com/brunoerg/bitcoinfuzz/issues/34
- rust-miniscript: https://github.com/rust-bitcoin/rust-miniscript/issues/696 (not found but reproductive) 
- rust-miniscript: https://github.com/brunoerg/bitcoinfuzz/issues/39
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/2891
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/2879
