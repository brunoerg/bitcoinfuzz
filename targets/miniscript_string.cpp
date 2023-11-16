#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <script/miniscript.h>

#include "miniscript_string.h"
#include "../compiler.h"

extern "C" bool rust_miniscript_from_str(std::string& miniscript_str);

void MiniscriptFromString(FuzzedDataProvider& provider) 
{
    std::string input_str{provider.ConsumeBytesAsString(provider.remaining_bytes() - 1)};
    if (input_str.size() == 1) return;
    auto ret{miniscript::FromString(input_str, COMPILER_CTX)};
    auto conditions = ret && ret->IsSane();
    std::cout << conditions << std::endl;
    std::cout << input_str << std::endl;
    assert(rust_miniscript_from_str(input_str) == conditions);
}

