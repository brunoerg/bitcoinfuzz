#include <assert.h>
#include <ctype.h>
#include <iostream>
#include <stdio.h>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>
#include <script/miniscript.h>

#include "targets.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);
    std::string target{std::getenv("FUZZ")}; 
    
    if (target == "miniscript_policy") {
        MiniscriptPolicy(provider);
    } else {
      std::exit(EXIT_SUCCESS);
    }
    
    return 0; // Values other than 0 and -1 are reserved for future use.
}
