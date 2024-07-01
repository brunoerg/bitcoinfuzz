#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "cmpctblocks.h"
#include "bitcoin/src/blockencodings.h"
#include "bitcoin/src/streams.h"

extern "C" char* rust_bitcoin_cmpctblocks(uint8_t *data, size_t len);

std::string CmpctBlocksCore(Span<const uint8_t> buffer) 
{
    DataStream ds{buffer};
    CBlockHeaderAndShortTxIDs block_header_and_short_txids;
    try {
        ds >> block_header_and_short_txids;
    } catch (const std::ios_base::failure& e) {
        if (std::string(e.what()).find("Superfluous witness record") != std::string::npos)
            return "Superfluous witness record";
        return "1";
    }
    return "0";
}

void CmpctBlocks(FuzzedDataProvider& provider)
{
    std::vector<uint8_t> buffer{provider.ConsumeRemainingBytes<uint8_t>()};
    std::string core{CmpctBlocksCore(buffer)};
    std::string rust_bitcoin{rust_bitcoin_cmpctblocks(buffer.data(), buffer.size())};

    if (core == "Superfluous witness record" || rust_bitcoin == "unsupported segwit version")
        return;

    assert(core == rust_bitcoin);
}