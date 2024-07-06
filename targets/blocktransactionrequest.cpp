#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>

#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/blockencodings.h"
#include "bitcoin/src/streams.h"

extern "C" int rust_bitcoin_blocktransactionrequests(const uint8_t *data, size_t len);

int BlockTransactionRequestCore(Span<const uint8_t> buffer) 
{
    DataStream ds{buffer};
    BlockTransactionsRequest request;
    int res = 0;
    try {
        ds >> request;
        res = request.indexes.size();
    } catch (const std::ios_base::failure& e) {
        if (std::string(e.what()).find("ReadCompactSize(): size too large") != std::string::npos)
            return -2;
        return -1;
    }
    return res;
}

FUZZ_TARGET(block_transaction_request)
{
    int core{BlockTransactionRequestCore(buffer)};
    int rust_bitcoin{rust_bitcoin_blocktransactionrequests(buffer.data(), buffer.size())};

    if (core == -2)
        return;

    assert(core == rust_bitcoin);
}