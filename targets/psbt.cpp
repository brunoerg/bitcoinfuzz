#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>

#include "psbt.h"

#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/psbt.h"
#include "bitcoin/src/span.h"
#include "bitcoin/src/node/psbt.h"

extern "C" char* rust_bitcoin_psbt(const uint8_t *data, size_t len);

bool PSBTCore(Span<const uint8_t> buffer)
{
    PartiallySignedTransaction psbt_mut;
    std::string error;
    if (!DecodeRawPSBT(psbt_mut, MakeByteSpan(buffer), error)) {
        return false;
    }
    return true;
}


FUZZ_TARGET(psbt)
{
    bool core{PSBTCore(buffer)};
    std::string rust_bitcoin{rust_bitcoin_psbt(buffer.data(), buffer.size())};
    if (rust_bitcoin == "invalid xonly public key" || 
        rust_bitcoin == "bitcoin consensus encoding error") return;
    if (core) assert(rust_bitcoin == "1");
    else assert(rust_bitcoin == "0");
}