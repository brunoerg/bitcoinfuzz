#include <assert.h>
#include <ctype.h>
#include <iostream>
#include <stdio.h>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "targets/miniscript_policy.h"
#include "targets/miniscript_string.h"
#include "targets/block_des.h"
#include "targets/prefilledtransaction.h"
#include "targets/tx_des.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);
    std::string target{std::getenv("FUZZ")}; 
    
    if (target == "miniscript_policy") {
        MiniscriptPolicy(provider);
    } else if (target == "miniscript_string") {
        MiniscriptFromString(provider);
    } else if (target == "block_deserialization") {
        BlockDes(provider);
    } else if (target == "prefilledtransaction") {
        PrefilledTransactionTarget(provider);
    } else if (target == "tx_deserialization") {
        TransactionDes(provider);
    } else {
      std::exit(EXIT_SUCCESS);
    }
    
    return 0; // Values other than 0 and -1 are reserved for future use.
}
