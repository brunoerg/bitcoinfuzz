#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>

#include "cmpctblocks.h"
#include "bitcoin/src/blockencodings.h"
#include "bitcoin/src/streams.h"

extern "C" int rust_bitcoin_cmpctblocks(uint8_t *data, size_t len);

int CmpctBlocksCore(Span<const uint8_t> buffer) 
{
    DataStream ds{buffer};
    CBlockHeaderAndShortTxIDs block_header_and_short_txids;
    try {
        ds >> block_header_and_short_txids;
    } catch (const std::ios_base::failure& e) {
        if (std::string(e.what()).find("Superfluous witness record") != std::string::npos)
            return -2;
        return -1;
    }
    return block_header_and_short_txids.BlockTxCount();
}

void CmpctBlocks(FuzzedDataProvider& provider)
{
    std::vector<uint8_t> buffer{provider.ConsumeRemainingBytes<uint8_t>()};
    int core{CmpctBlocksCore(buffer)};
    int rust_bitcoin{rust_bitcoin_cmpctblocks(buffer.data(), buffer.size())};

    if (core == -2 || rust_bitcoin == -2)
        return;

    assert(core == rust_bitcoin);
}