#include <fuzzer/FuzzedDataProvider.h>
#include <string_view>
#include <iostream>

#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/protocol.h"
#include "bitcoin/src/hash.h"

using namespace std::string_view_literals;

extern "C" int rust_bitcoin_rawmessage(const uint8_t *data, size_t len);
extern "C" int go_btcd_rawmessage(const uint8_t *data, size_t len);

/**
 * This is a list of all the supported message types in btcd
 * and we will only fuzz these message types.
 * Note: This is missing message types related to compact blocks
 * as compact blocks is not supported by btcd.
 */
static constexpr std::array LUT {
//  "version"sv,  // unstable because btcd supports older versions of the protocol while rust-bitcoin does not
    "verack"sv,
    "getaddr"sv,
    "addr"sv,
//  "addrv2"sv,  // Fuzz using the addrv2 target
    "getblocks"sv,
    "inv"sv,
    "getdata"sv,
    "notfound"sv,
//  "block"sv,  // Fuzz using the block_des target
//  "tx"sv,  // // Fuzz using the tx_des target
    "getheaders"sv,
    "headers"sv,
    "ping"sv,
    "pong"sv,
    "alert"sv,
    "mempool"sv,
    "filteradd"sv,
    "filterclear"sv,
    "filterload"sv,
    "merkleblock"sv,
    "reject"sv,
    "sendheaders"sv,
    "feefilter"sv,
    "getcfilters"sv,
    "getcfheaders"sv,
    "getcfcheckpt"sv,
    "cfilter"sv,
    "cfheaders"sv,
    "cfcheckpt"sv,
    "sendaddrv2"sv
};

namespace {
    int8_t g_type {-1};  // -1 = All
} // namespace

void initializeAndPerformChecks()
{
    if (const auto val{std::getenv("LIMIT_TO_MESSAGE_TYPE")}) {
        for (int i = 0; i < LUT.size(); i++) {
            if (LUT[i] == val) {
                g_type = i;
            }
        }
    }

    /**
     * Manual patches are needed to be applied to btcd and rust bitcoin
     * to remove checking of checksum and the max payload size of a message.
     * Refer to the patches/ directory for additional info.
     * We'll check if these patches have been applied and fail incase they have not.
     */

    // Check whether patches have been applied
    CMessageHeader header({0xf9, 0xbe, 0xb4, 0xd9}, "verack", 4);
    header.pchChecksum[0] = 0; // should pass with a checksum value of 0

    DataStream ds;
    ds << header;
    ds << 0xdfdfdfdf;

    auto btcd{go_btcd_rawmessage((uint8_t*)ds.data(), ds.size())};
    auto rust_bitcoin{rust_bitcoin_rawmessage((uint8_t*)ds.data(), ds.size())};

    assert(rust_bitcoin == 0 || ("Rust bitcoin has not been patched." == nullptr));
    assert(btcd == 0 || ("BTCD has not been patched." == nullptr));
}

FUZZ_TARGET(raw_message_des, .init = initializeAndPerformChecks)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    if (provider.remaining_bytes() < 2)
        return;

    const auto msgtype = g_type != -1 ? LUT[g_type] : LUT[provider.ConsumeIntegral<uint8_t>() % LUT.size()];
    CMessageHeader header({0xf9, 0xbe, 0xb4, 0xd9}, msgtype.data(), provider.remaining_bytes());

    DataStream ds;
    ds << header;
    ds << provider.ConsumeRemainingBytes<uint8_t>();

    auto btcd{go_btcd_rawmessage((uint8_t*)ds.data(), ds.size())};
    auto rust_bitcoin{rust_bitcoin_rawmessage((uint8_t*)ds.data(), ds.size())};

    if (rust_bitcoin == -2)
        return;

    assert(btcd == rust_bitcoin);
}