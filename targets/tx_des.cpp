#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>

#include "tx_des.h"
#include "../bitcoin/primitives/block.h"
#include "../bitcoin/streams.h"
extern "C" char* go_btcd_des_tx(uint8_t *data, size_t len);

std::string TransactionDesCore(Span<const uint8_t> buffer)
{
    DataStream ds{buffer};
    CMutableTransaction tx;
    try {
        ds >> TX_WITH_WITNESS(tx);
        return tx.GetHash().ToString();
    } catch (const std::ios_base::failure&) {
        return "";
    }
    return "";
}

// This target is expected to crash, needs some verification (e.g. segwit version).
void TransactionDes(FuzzedDataProvider& provider) 
{
    std::vector<uint8_t> buffer{provider.ConsumeRemainingBytes<uint8_t>()};

    std::string core{TransactionDesCore(buffer)};
    std::string go_btcd{go_btcd_des_tx(buffer.data(), buffer.size())};
    assert(core == go_btcd);
}