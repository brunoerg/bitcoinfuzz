# tmi2

Wraps [tmi2](https://github.com/theuni/tmi2), a slimmed-down reimplementation of
`boost::multi_index` intended as a near drop-in replacement for Bitcoin Core's
usage, for the `multi_index` differential target. The target runs the same
container op sequence (insert, emplace, erase, find, count, bounds, modify,
clear) against every loaded multi-index implementation and compares the
observable results; its counterpart module is
[Boost.MultiIndex](../boostmultiindex/README.md), which acts as the reference
implementation.

The op sequence and trace comparison live in
[`include/bitcoinfuzz/multiindex_harness.h`](../../include/bitcoinfuzz/multiindex_harness.h),
shared by both modules; this module only instantiates the tmi container.

Two op groups are currently compiled out via flags at the top of the harness
header (`kEnableModifyOps`, `kEnableClearOps`) because they hit known tmi2 bugs;
flip them back on once the upstream fixes land.

## Build

tmi2 is header-only; the pinned `external/tmi2` submodule provides the code
under test:

```bash
git submodule update --init external/tmi2
cd modules/tmi2
make
```

Then compile bitcoinfuzz with `-DTMI2` and run:

```bash
FUZZ=multi_index MODULES=BOOST_MULTI_INDEX,TMI2 ./bitcoinfuzz
```
