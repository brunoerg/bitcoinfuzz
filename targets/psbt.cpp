#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>

#include "psbt.h"
#include "bitcoin/src/psbt.h"
#include "bitcoin/src/span.h"
#include "bitcoin/src/node/psbt.h"

extern "C" char* rust_bitcoin_psbt(uint8_t *data, size_t len);
extern "C" char* go_btcd_psbt(uint8_t *data, size_t len);

bool PSBTCore(Span<const uint8_t> buffer)
{
    PartiallySignedTransaction psbt_mut;
    std::string error;
    if (!DecodeRawPSBT(psbt_mut, MakeByteSpan(buffer), error)) {
        return false;
    }
    return true;
}


void Psbt(FuzzedDataProvider& provider)
{
    std::vector<uint8_t> buffer{provider.ConsumeRemainingBytes<uint8_t>()};
    bool core{PSBTCore(buffer)};
    std::string rust_bitcoin{rust_bitcoin_psbt(buffer.data(), buffer.size())};
    //std::string btcd {go_btcd_psbt(buffer.data(), buffer.size())};

    if (rust_bitcoin == "invalid xonly public key" || 
        rust_bitcoin == "bitcoin consensus encoding error") return;
    if (core) assert(rust_bitcoin == "1");
    else assert(rust_bitcoin == "0");

    // BTCD PSBT code is currently unstable - and will crash really fast
    // if (core) assert(btcd == "1");
    // else assert(btcd == "0");
}