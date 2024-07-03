#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <stdio.h>

#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/consensus/tx_check.h"
#include "bitcoin/src/consensus/validation.h"
#include "bitcoin/src/primitives/block.h"
#include "bitcoin/src/streams.h"

extern "C" char* go_btcd_des_tx(const uint8_t *data, size_t len);

std::string TransactionDesCore(Span<const uint8_t> buffer)
{
    DataStream ds{buffer};
    CMutableTransaction tx;
    try {
        ds >> TX_WITH_WITNESS(tx);
    } catch (const std::ios_base::failure&) {
        return "";
    }

    TxValidationState state;
    CTransaction tx_def{tx};
    const bool res{CheckTransaction(tx_def, state)};
    if (res) return tx.GetHash().ToString();
    return "";
}

FUZZ_TARGET(transaction_des)
{
    std::string core{TransactionDesCore(buffer)};
    std::string go_btcd{go_btcd_des_tx(buffer.data(), buffer.size())};
    assert(core == go_btcd);
}