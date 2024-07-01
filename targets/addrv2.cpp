#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <optional>
#include <stdio.h>

#include "addrv2.h"
#include "bitcoin/src/protocol.h"
#include "bitcoin/src/streams.h"

extern "C" bool rust_bitcoin_addrv2(uint8_t *data, size_t len, uint64_t *count);
extern "C" bool go_btcd_addrv2(uint8_t *data, size_t len, uint64_t *count);

std::optional<std::pair<uint64_t, uint64_t>> Addrv2Core(Span<const uint8_t> buffer) 
{
    std::vector<CAddress> addrs;
    DataStream ds{buffer};
    uint64_t clearnet_count{0};
    try {
        ds >> CAddress::V2_NETWORK(addrs);
        if (addrs.size() > 1000) return std::nullopt;
        for (auto& addr : addrs) {
            if (addr.IsIPv4() || addr.IsIPv6()) clearnet_count++;
            if (!addr.IsValid()) return std::nullopt;
        }
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }

    return std::make_pair(addrs.size(), clearnet_count);
}

void Addrv2(FuzzedDataProvider& provider)
{
    std::vector<uint8_t> buffer{provider.ConsumeRemainingBytes<uint8_t>()};
    uint64_t count_rust = 0, count_btcd = 0;
    [[maybe_unused]] bool rust_bitcoin{rust_bitcoin_addrv2(buffer.data(), buffer.size(), &count_rust)};
    [[maybe_unused]] bool btcd{go_btcd_addrv2(buffer.data(), buffer.size(), &count_btcd)};
    auto core{Addrv2Core(buffer)};
    if (core.has_value() && core->first > 0) {
        assert(core->first == count_rust);
        assert(core->second == count_btcd);
    }
}