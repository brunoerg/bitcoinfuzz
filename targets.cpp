#include <fuzzer/FuzzedDataProvider.h>
#include <script/miniscript.h>
#include <string>

#include "targets.h"
#include "compiler.h"

extern "C" bool miniscript_policy(std::string& policy);

void MiniscriptPolicy(FuzzedDataProvider& provider) {
    auto input_str{provider.ConsumeBytesAsString(provider.remaining_bytes() - 1)};
    assert(ParsePolicy(input_str) == miniscript_policy(input_str));
}