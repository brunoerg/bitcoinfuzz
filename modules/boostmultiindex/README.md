# Boost.MultiIndex

Wraps [Boost.MultiIndex](https://github.com/boostorg/multi_index) for the
`multi_index` differential target, which runs the same container op sequence
(insert, emplace, erase, find, count, bounds, modify, clear) against every
loaded multi-index implementation and compares the observable results. Its
counterpart module is [tmi2](../tmi2/README.md), a from-scratch reimplementation
intended as a drop-in replacement for Bitcoin Core's Boost.MultiIndex usage.

The op sequence and trace comparison live in
[`include/bitcoinfuzz/multiindex_harness.h`](../../include/bitcoinfuzz/multiindex_harness.h),
shared by both modules; this module only instantiates the Boost container.

The module also participates in four focused single-index targets alongside
tmi2 and the matching standard associative containers:
`multi_index_ordered_unique`, `multi_index_ordered_non_unique`,
`multi_index_hashed_unique`, and `multi_index_hashed_non_unique`.

## Build

The pinned `external/multi_index` and `external/boost-mp11` submodules provide
the code under test; system Boost supplies the remaining header-only support
libraries (`BOOST_ROOT` defaults to `/usr` on Linux and the Homebrew prefix on
macOS):

```bash
git submodule update --init external/multi_index external/boost-mp11
cd modules/boostmultiindex
make
```

Then compile bitcoinfuzz with `-DBOOST_MULTI_INDEX` and run:

```bash
FUZZ=multi_index MODULES=BOOST_MULTI_INDEX,TMI2 ./bitcoinfuzz
```

For example, run a focused target with:

```bash
FUZZ=multi_index_ordered_unique \
MODULES=BOOST_MULTI_INDEX,TMI2,STD_CONTAINERS \
./bitcoinfuzz
```
