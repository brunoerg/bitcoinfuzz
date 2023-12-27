#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <script/miniscript.h>

#include "miniscript_string.h"
#include "../compiler.h"

extern "C" bool rust_miniscript_from_str(const char* miniscript_str);

bool BitcoinCoreString(const std::string& input_str)
{
    auto ret{miniscript::FromString(input_str, COMPILER_CTX)};
    if (!ret || !ret->IsSane()) return false;
    return true;
}

void MiniscriptFromString(FuzzedDataProvider& provider) 
{
    std::string input_str{provider.ConsumeRemainingBytesAsString().c_str()};
    // See: https://github.com/rust-bitcoin/rust-miniscript/issues/633
    if (input_str.find("l:0") != std::string::npos) return;
    const bool core{BitcoinCoreString(input_str)};
    const bool rust_miniscript{rust_miniscript_from_str(input_str.c_str())};
    assert(core == rust_miniscript);
}

