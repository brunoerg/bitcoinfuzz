#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <stdio.h>

#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/streams.h"
#include "bitcoin/src/script/script.h"

extern "C" bool rust_bitcoin_script(const uint8_t *data, size_t len);

bool CoreScript(Span<const uint8_t> buffer)
{
    DataStream ds{buffer};
    CScript script;
    try {
        ds >> script;
    } catch (const std::ios_base::failure& e) {
        return false;
    }
    if (script.IsUnspendable()) return false;
    return true;
}


FUZZ_TARGET(script)
{
    bool core{CoreScript(buffer)};
    bool rust_bitcoin{rust_bitcoin_script(buffer.data(), buffer.size())};
    assert(core == rust_bitcoin);
}