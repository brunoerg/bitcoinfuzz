#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <script/miniscript.h>

#include "miniscript_string.h"
#include "../compiler.h"

extern "C" bool rust_miniscript_from_str(std::string& miniscript_str);

bool BitcoinCore(const std::string& input_str)
{
    auto ret{miniscript::FromString(input_str, COMPILER_CTX)};
    if (!ret || !ret->IsValidTopLevel()) return false;
    return true;
}

void MiniscriptFromString(FuzzedDataProvider& provider) 
{
    std::string input_str{provider.ConsumeRemainingBytesAsString().c_str()};
    bool core{BitcoinCore(input_str)};
    bool rust_miniscript{rust_miniscript_from_str(input_str)};
    if (rust_miniscript) assert(core);
}

