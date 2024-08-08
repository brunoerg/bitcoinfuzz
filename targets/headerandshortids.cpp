#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>

#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/blockencodings.h"
#include "bitcoin/src/streams.h"

extern "C" int rust_bitcoin_headerandshortids(const uint8_t *data, size_t len);

int HeaderAndShortIdsCore(Span<const uint8_t> buffer) 
{
    DataStream ds{buffer};
    CBlock block;
    int res = 0;
    try {
        ds >> TX_WITH_WITNESS(block);
        if (block.vtx.size() < 1) return res;
        CBlockHeaderAndShortTxIDs block_header_and_short_txids {block, 101}; // use the value of 101 as nonce
        res = block_header_and_short_txids.BlockTxCount();
    } catch (const std::ios_base::failure& e) {
        if (std::string(e.what()).find("Superfluous witness record") != std::string::npos)
            return -2;
        return -1;
    }
    return res;
}

FUZZ_TARGET(header_and_shortids)
{
    int core{HeaderAndShortIdsCore(buffer)};
    int rust_bitcoin{rust_bitcoin_headerandshortids(buffer.data(), buffer.size())};

    if (core == -2 || rust_bitcoin == -2)
        return;

    assert(core == rust_bitcoin);
}