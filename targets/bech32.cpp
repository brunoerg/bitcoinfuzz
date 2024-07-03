#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>

#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/bech32.h"
#include "bitcoin/src/streams.h"

extern "C" char* go_btcd_bech32(const uint8_t *data, size_t len);

std::string Bech32Core(Span<const uint8_t> buffer)
{
    const std::string random_string(buffer.begin(), buffer.end());
    const auto r1 = bech32::Decode(random_string);
    if (r1.encoding == bech32::Encoding::INVALID) {
        return "";
    }
    return r1.hrp;
}


FUZZ_TARGET(bech32)
{
    std::string core{Bech32Core(buffer)};
    std::string go_btcd{go_btcd_bech32(buffer.data(), buffer.size())};

    assert(go_btcd == core);
}