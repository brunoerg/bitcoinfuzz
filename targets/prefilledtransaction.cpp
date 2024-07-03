#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>

#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/blockencodings.h"
#include "bitcoin/src/streams.h"

extern "C" char* rust_bitcoin_prefilledtransaction(const uint8_t *data, size_t len);

std::optional<uint16_t> PrefilledTransactionCore(Span<const uint8_t> buffer)
{
    DataStream ds{buffer};
    PrefilledTransaction tx;
    try {
        ds >> tx;
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
    return tx.index;
}

FUZZ_TARGET(prefilled_transaction)
{
    auto core{PrefilledTransactionCore(buffer)};
    std::string rust_bitcoin{rust_bitcoin_prefilledtransaction(buffer.data(), buffer.size())};
    if (rust_bitcoin == "unsupported segwit version") return;
    if (core.has_value()) assert(rust_bitcoin != "");
    else assert(rust_bitcoin == "");
}
