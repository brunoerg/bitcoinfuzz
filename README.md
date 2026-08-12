# bitcoinfuzz

Differential Fuzzing of Bitcoin implementations and libraries.
Note this project is a WIP and might be not stable.

# Installation

## Platform Support

*bitcoinfuzz is developed and supported on Linux only.*

### MacOS or Windows Users:

We recommend using Docker to run bitcoinfuzz if you're on macOS or Windows. This provides the most reliable fuzzing experience with full toolchain support.

## Dependencies

### llvm toolset (clang and libfuzzer)

* To support the flags used in some modules `-fsanitize=address,fuzzer -std=c++20` the minimum clang version required is 10.0

* For ubuntu/debian it can be installed using the package manager:
    ```
    sudo apt install clang lld llvm-dev
    ```

* To install it from source check [clang_get_started](https://clang.llvm.org/get_started.html). You must build it with this cmake option: `-DLLVM_ENABLE_PROJECTS="clang;lld;compiler-rt"`

# Running

The fuzzer has a lot of dependencies from the number of projects (and their runtime/lang) it supports and for that reason we provide a docker workflow to ease the burden of setting up and building the project.

See [RUNNING.md](./RUNNING.md) to understand better the options and their configurations.

If you ended up luckily finding more bugs report them responsibly (see the respective SECURITY.md file on the project repo). You can merge your fuzzing corpus with our [public corpora](https://github.com/bitcoinfuzz/corpora).


# Fuzzing with AFL++

To quickly get started fuzzing using [afl++](https://github.com/AFLplusplus/AFLplusplus):

```sh
$ git clone https://github.com/AFLplusplus/AFLplusplus
$ make -C AFLplusplus/ source-only
# To choose/use any other afl compiler, see
# https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#a-selecting-the-best-afl-compiler-for-instrumenting-the-target
$ CC="AFLplusplus/afl-clang-fast" CXX="AFLplusplus/afl-clang-fast++" make
$ mkdir -p inputs/ outputs/
$ echo A > inputs/thin-air-input
$ FUZZ=addrv2 ./AFLplusplus/afl-fuzz -i inputs/ -o outputs/ -- ./bitcoinfuzz
```

If you want the same workflow in a container, see the AFL++ Docker section in
[RUNNING.md](./RUNNING.md), which includes build/run examples, corpus
persistence, resume behavior, and the Linux `core_pattern` caveat.

Read the [afl++ documentation](https://github.com/AFLplusplus/AFLplusplus) for more information.

# Build Options

You can build the modules in two ways: **manual** or **automatic**. The automatic method is provided by the `scripts/auto_build.py` script, which simplifies the build and clean processes. Additionally, you can use **Docker** or **Docker Compose** to run the application without installing dependencies directly on your machine.

## Automatic Method: `auto_build.py`

The `auto_build.py` script allows you to automatically build the modules based on the flags defined in `CXXFLAGS`. It also provides options to clean the builds before compiling.

### How to use:

1. **Automatic Build**:
   - To automatically build the modules, define the flags in `CXXFLAGS` and run the script:
     ```bash
     CXXFLAGS="-DLDK -DLND" ./scripts/auto_build.py
     ```
     This will automatically build the `LDK` and `LND` modules.

2. **Automatic Clean**:
   - The script supports three cleaning modes before building:
     - **Full Clean**: Cleans all modules before building the selected ones.
       ```bash
       CLEAN_BUILD="FULL" CXXFLAGS="-DLDK -DLND" ./scripts/auto_build.py
       ```
     - **Clean**: Cleans only the modules that will be built based on `CXXFLAGS`.
       ```bash
       CLEAN_BUILD="CLEAN" CXXFLAGS="-DLDK -DLND" ./scripts/auto_build.py
       ```
     - **Select Clean**: Cleans specific modules defined in `CLEAN_BUILD`, regardless of `CXXFLAGS`.
       ```bash
       CLEAN_BUILD="-DLDK -DBTCD" CXXFLAGS="-DLDK -DLND" ./scripts/auto_build.py
       ```
       In this case, the script will run `make clean` for `LDK` and `BTCD`, but will only build the modules defined in `CXXFLAGS` (`LDK` and `LND`).

## Docker

See [RUNNING.md](./RUNNING.md) for more information.

## Manual Method

If you prefer, you can still build the modules manually. Each module's README.md
contains the module-specific build commands, dependencies, and notes.

### Bitcoin modules:

| Module | CXXFLAGS define | Instructions |
| --- | --- | --- |
| [Bitcoin Core](https://github.com/bitcoin/bitcoin) | `BITCOIN_CORE` | [modules/bitcoin/README.md](./modules/bitcoin/README.md) |
| [bitcoinerlab miniscript](https://github.com/bitcoinerlab/miniscript) | `BITCOINERLAB_MINISCRIPT` | [modules/bitcoinerlabminiscript/README.md](./modules/bitcoinerlabminiscript/README.md) |
| [bitcoinj](https://github.com/bitcoinj/bitcoinj) | `BITCOINJ` | [modules/bitcoinj/README.md](./modules/bitcoinj/README.md) |
| [bitcoinkernel](https://github.com/bitcoin/bitcoin/blob/master/src/kernel/bitcoinkernel.cpp) | `BITCOINKERNEL` | [modules/bitcoinkernel/README.md](./modules/bitcoinkernel/README.md) |
| bitcoinkernel-variant | `BITCOINKERNEL_VARIANT` | [modules/bitcoinkernelvariant/README.md](./modules/bitcoinkernelvariant/README.md) |
| [bitcoin-s](https://github.com/bitcoin-s/bitcoin-s) | `BITCOINS` | [modules/bitcoins/README.md](./modules/bitcoins/README.md) |
| [btcd](https://github.com/btcsuite/btcd) | `BTCD` | [modules/btcd/README.md](./modules/btcd/README.md) |
| [embit](https://github.com/diybitcoinhardware/embit) | `EMBIT` | [modules/embit/README.md](./modules/embit/README.md) |
| [gocoin](https://github.com/piotrnar/gocoin) | `GOCOIN` | [modules/gocoin/README.md](./modules/gocoin/README.md) |
| [libbitcoin-system](https://github.com/libbitcoin/libbitcoin-system) | `LIBBITCOIN_SYSTEM` | [modules/libbitcoinsystem/README.md](./modules/libbitcoinsystem/README.md) |
| [libwally-core](https://github.com/ElementsProject/libwally-core) | `LIBWALLY_CORE` | [modules/libwallycore/README.md](./modules/libwallycore/README.md) |
| [NBitcoin](https://github.com/MetacoSA/NBitcoin) | `NBITCOIN` | [modules/nbitcoin/README.md](./modules/nbitcoin/README.md) |
| [py-bitcoinkernel](https://github.com/stickies-v/py-bitcoinkernel) | `PYBITCOINKERNEL` | [modules/pybitcoinkernel/README.md](./modules/pybitcoinkernel/README.md) |
| [pycoin](https://github.com/richardkiss/pycoin) | `PYCOIN` | [modules/pycoin/README.md](./modules/pycoin/README.md) |
| [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) | `RUST_BITCOIN` | [modules/rustbitcoin/README.md](./modules/rustbitcoin/README.md) |
| [rust-bitcoinkernel](https://github.com/sedited/rust-bitcoinkernel) | `RUSTBITCOINKERNEL` | [modules/rustbitcoinkernel/README.md](./modules/rustbitcoinkernel/README.md) |
| [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) | `RUST_MINISCRIPT` | [modules/rustminiscript/README.md](./modules/rustminiscript/README.md) |
| [rust-psbt](https://github.com/rust-bitcoin/rust-psbt) | `RUST_PSBT` | [modules/rustpsbt/README.md](./modules/rustpsbt/README.md) |
| [tinyminiscript](https://github.com/unldenis/tinyminiscript) | `TINY_MINISCRIPT` | [modules/tinyminiscript/README.md](./modules/tinyminiscript/README.md) |

### Lightning modules:

| Module | CXXFLAGS define | Instructions |
| --- | --- | --- |
| [C-lightning](https://github.com/ElementsProject/lightning) | `CLIGHTNING` | [modules/clightning/README.md](./modules/clightning/README.md) |
| [Eclair](https://github.com/ACINQ/eclair) | `ECLAIR` | [modules/eclair/README.md](./modules/eclair/README.md) |
| [LDK](https://github.com/lightningdevkit/rust-lightning) | `LDK` | [modules/ldk/README.md](./modules/ldk/README.md) |
| [lightning-kmp](https://github.com/ACINQ/lightning-kmp) | `LIGHTNING_KMP` | [modules/lightningkmp/README.md](./modules/lightningkmp/README.md) |
| [LND](https://github.com/lightningnetwork/lnd) | `LND` | [modules/lnd/README.md](./modules/lnd/README.md) |
| [NLightning](https://github.com/ipms-io/nlightning) | `NLIGHTNING` | [modules/nlightning/README.md](./modules/nlightning/README.md) |

### Cryptography modules:

| Module | CXXFLAGS define | Instructions |
| --- | --- | --- |
| [Decred-Secp256k1](https://github.com/decred/dcrd/tree/master/dcrec/secp256k1) | `DECRED_SECP256K1` | [modules/decredsecp256k1/README.md](./modules/decredsecp256k1/README.md) |
| [K256](https://github.com/RustCrypto/elliptic-curves/tree/master/k256) | `RUST_K256` | [modules/rustk256/README.md](./modules/rustk256/README.md) |
| [Libsecp256k1](https://github.com/bitcoin-core/secp256k1) | `SECP256K1` | [modules/secp256k1/README.md](./modules/secp256k1/README.md) |
| [NBitcoin-Secp256k1](https://github.com/MetacoSA/NBitcoin/tree/master/NBitcoin.Secp256k1) | `NBITCOIN_SECP256K1` | [modules/nbitcoinsecp256k1/README.md](./modules/nbitcoinsecp256k1/README.md) |
| [rust-musig2](https://github.com/conduition/rust-musig2) | `RUST_MUSIG2` | [modules/rustmusig2/README.md](./modules/rustmusig2/README.md) |
| [RustCrypto AES](https://github.com/RustCrypto/block-ciphers/tree/master/aes) | `RUSTCRYPTO_AES` | [modules/rustcryptoaes/README.md](./modules/rustcryptoaes/README.md) |

### Utreexo Modules

| Module | CXXFLAGS define | Instructions |
| --- | --- | --- |
| [Rustreexo](https://github.com/mit-dci/rustreexo) | `RUSTREEXO` | [modules/rustreexo/README.md](./modules/rustreexo/README.md) |
| [Utreexo](https://github.com/utreexo/utreexo) | `UTREEXO` | [modules/utreexo/README.md](./modules/utreexo/README.md) |

### Container Modules

| Module | CXXFLAGS define | Instructions |
| --- | --- | --- |
| [Boost.MultiIndex](https://github.com/boostorg/multi_index) | `BOOST_MULTI_INDEX` | [modules/boostmultiindex/README.md](./modules/boostmultiindex/README.md) |
| [tmi2](https://github.com/theuni/tmi2) | `TMI2` | [modules/tmi2/README.md](./modules/tmi2/README.md) |
| Standard associative containers | `STD_CONTAINERS` | [modules/stdcontainers/README.md](./modules/stdcontainers/README.md) |

## Final Build and Execution
Once the modules are compiled, you can compile `bitcoinfuzz` and execute it:

```bash
make
FUZZ=target_name ./bitcoinfuzz
```

## Selective Module Loading

By default, all compiled modules are loaded when running the fuzzer. You can use the `MODULES` environment variable to load only specific modules at runtime, **without needing to recompile**.

### Usage

Set the `MODULES` environment variable to a comma-separated list of module names:

```bash
MODULES="BITCOIN_CORE,RUST_BITCOIN" FUZZ=target_name ./bitcoinfuzz
```

### Examples

Load only Bitcoin Core and rust-bitcoin for comparison:
```bash
MODULES="BITCOIN_CORE,RUST_BITCOIN" FUZZ=bip32_master_keygen ./bitcoinfuzz
```

Load Lightning implementations only:
```bash
MODULES="LDK,LND,CLIGHTNING" FUZZ=deserialize_invoice ./bitcoinfuzz
```

Load all compiled modules (default behavior):
```bash
FUZZ=target_name ./bitcoinfuzz
```

### Notes

- If `MODULES` is unset or empty, all compiled modules are loaded (existing behavior)
- The fuzzer will abort with an error if you request a module that was not compiled
- Whitespace around module names is trimmed (e.g., `"BTCD, LND"` works)

## Logging Module Outputs

Set `LOG_OUTPUTS=1` to print every accepted module response in the form:

```
Module: <module_name>
Result: <response>
```

This is independent of mismatch reporting (which always runs) and is useful for
debugging or manually inspecting what each module returns for a given input.
Expect very noisy output during fuzzing.

```bash
LOG_OUTPUTS=1 FUZZ=address_parse ./bitcoinfuzz crash-xxxx
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
- btcd: https://github.com/btcsuite/btcd/issues/2199
- rust-bitcoin: https://github.com/brunoerg/bitcoinfuzz/issues/57
- rust-miniscript: CVE-2024-44073
- rust-miniscript: https://github.com/rust-bitcoin/rust-miniscript/issues/785
- rust-miniscript: https://github.com/rust-bitcoin/rust-miniscript/issues/788
- LND: https://github.com/lightningnetwork/lnd/issues/9591
- Embit: https://github.com/diybitcoinhardware/embit/issues/70
- btcd: https://github.com/btcsuite/btcd/issues/2351
- Core Lightning: https://github.com/ElementsProject/lightning/pull/8219
- LND: https://github.com/lightningnetwork/lnd/issues/9808
- Core Lightning:  https://github.com/ElementsProject/lightning/pull/8282
- btcd: https://github.com/btcsuite/btcd/issues/2372
- bolts: https://github.com/lightning/bolts/pull/1264
- rust-lightning: https://github.com/lightningdevkit/rust-lightning/pull/3814
- LND: https://github.com/lightningnetwork/lnd/issues/9904
- LND: https://github.com/lightningnetwork/lnd/issues/9915
- Eclair: https://github.com/ACINQ/eclair/issues/3104
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/4617
- NBitcoin: https://github.com/MetacoSA/NBitcoin/issues/1278
- lightning-kmp: https://github.com/ACINQ/lightning-kmp/issues/799
- lightning-kmp: https://github.com/ACINQ/lightning-kmp/pull/801
- bitcoin-kmp: https://github.com/ACINQ/bitcoin-kmp/issues/157
- secp256k1: https://github.com/bitcoin-core/secp256k1/issues/1718
- lightning-kmp: https://github.com/ACINQ/lightning-kmp/issues/802
- rust-lightning: https://github.com/lightningdevkit/rust-lightning/pull/3998
- bolts: https://github.com/lightning/bolts/pull/1279
- rust-lightning: https://github.com/lightningdevkit/rust-lightning/pull/4018
- btcd: https://github.com/btcsuite/btcd/issues/2402
- btcd: https://github.com/btcsuite/btcd/issues/2424
- rust-lightning: https://github.com/lightningdevkit/rust-lightning/pull/4090
- btcd: https://github.com/btcsuite/btcd/issues/2431
- LND: https://github.com/lightningnetwork/lnd/pull/10249
- NBitcoin: https://github.com/MetacoSA/NBitcoin/issues/1283
- tinyminiscript: https://github.com/unldenis/tinyminiscript/issues/54
- NBitcoin: https://github.com/MetacoSA/NBitcoin/pull/1288
- bolts: https://github.com/lightning/bolts/pull/1303
- lightning-onion: https://github.com/lightningnetwork/lightning-onion/pull/74
- NBitcoin: https://github.com/MetacoSA/NBitcoin/pull/1294
- Floresta: https://github.com/bitcoinfuzz/bitcoinfuzz/issues/383 / https://github.com/getfloresta/Floresta/pull/781
- gocoin: https://github.com/piotrnar/gocoin/commit/42763e1efb5f09ab563aa95a288b1dbe92b90cce
- bitcoinj: https://github.com/bitcoinj/bitcoinj/issues/4054
- libwally-core: https://github.com/ElementsProject/libwally-core/commit/a3fd0aa8ba78d37819ea3b03d22c77028e958cf5
- libwally-core: https://github.com/ElementsProject/libwally-core/commit/a1de7372913092cc664ceb98e7b96dd57fec44e7
- NBitcoin: https://github.com/MetacoSA/NBitcoin/issues/1297
- btcd: https://github.com/btcsuite/btcd/pull/2485
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/5617
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/5697
- LND: https://github.com/lightningnetwork/lnd/pull/10597
- gocoin: https://github.com/piotrnar/gocoin/commit/3234dfcf5433718a5aa521db618e40f7c89c3690
- rust-lightning: https://github.com/lightningdevkit/rust-lightning/issues/4442
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/5730
- utreexo: https://github.com/utreexo/utreexo/issues/190
- libwally-core: https://github.com/ElementsProject/libwally-core/pull/521
- pycoin: https://github.com/richardkiss/pycoin/issues/437
- embit: https://github.com/diybitcoinhardware/embit/issues/113
- btcd: https://github.com/btcsuite/btcd/pull/2525
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/pull/1829
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/pull/1836
- libwally-core: https://github.com/ElementsProject/libwally-core/issues/528
- Bitcoin Core: https://github.com/bitcoin/bitcoin/issues/35308
- embit: https://github.com/diybitcoinhardware/embit/issues/127
- Bitcoin-S: https://github.com/bitcoin-s/bitcoin-s/issues/6350
- NBitcoin: https://github.com/MetacoSA/NBitcoin/issues/1301
- pycoin: https://github.com/richardkiss/pycoin/issues/438
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin/issues/6199
- bitcoinj: https://github.com/bitcoinj/bitcoinj/pull/4210
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/pull/1837
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/pull/1840
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/pull/1860
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/pull/1871
- bitcoin-s: https://github.com/bitcoin-s/bitcoin-s/issues/6411
- embit: https://github.com/diybitcoinhardware/embit/issues/146
- tmi2: https://github.com/theuni/tmi2/pull/4 (3 different bugs)
- bolts: https://github.com/lightning/bolts/pull/1284
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/commit/5427420d7d34d6c5100921612f4afdece935fbee
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/commit/8f498571121f99aa777fed32c17cbf007a66dea4
- libbitcoin-system: https://github.com/libbitcoin/libbitcoin-system/commit/cfbfbb183693d9995737f146b86ebbe77d0214af
- embit: https://github.com/diybitcoinhardware/embit/pull/149
- libwally-core: https://github.com/ElementsProject/libwally-core/pull/541
- NBitcoin: https://github.com/MetacoSA/NBitcoin/pull/1327
- gocoin: https://github.com/piotrnar/gocoin/commit/b021b1c2cd3777716bd8f09ac66d7e89d2996469
