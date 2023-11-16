#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "miniscript_policy.h"
#include "../compiler.h"

extern "C" bool rust_miniscript_policy(std::string& policy);

void MiniscriptPolicy(FuzzedDataProvider& provider) {
    auto input_str{provider.ConsumeBytesAsString(provider.remaining_bytes() - 1)};
    assert(ParsePolicy(input_str) == rust_miniscript_policy(input_str));
}