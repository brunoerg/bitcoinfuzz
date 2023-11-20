#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>

#include "miniscript_policy.h"
#include "../compiler.h"

extern "C" bool rust_miniscript_policy(const char* policy);

bool BitcoinCorePolicy(const std::string& input_str)
{
    return ParsePolicy(input_str);
}

void MiniscriptPolicy(FuzzedDataProvider& provider) 
{
    std::string input_str{provider.ConsumeRemainingBytesAsString()};
    assert(BitcoinCorePolicy(input_str) == rust_miniscript_policy(input_str.c_str()));
}