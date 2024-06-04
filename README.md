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

Once the compilation is complete bitcoinfuzz can be executed by:

```bash
FUZZ=target_name ./bitcoinfuzz
```

-------------------------------------------
### Bugs/inconsistences found by Bitcoinfuzz

- sipa/miniscript: https://github.com/sipa/miniscript/issues/140
- rust-miniscript: https://github.com/rust-bitcoin/rust-miniscript/issues/633
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/2681
