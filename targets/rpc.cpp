// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Following file has been modified by bitcoinfuzz contributors to 
// better suit their purpose. All credits go the original authors.

#include "bitcoin/src/base58.h"
#include "bitcoin/src/key.h"
#include "bitcoin/src/key_io.h"
#include "bitcoin/src/primitives/block.h"
#include "bitcoin/src/primitives/transaction.h"
#include "bitcoin/src/rpc/client.h"
#include "bitcoin/src/rpc/request.h"
#include "bitcoin/src/rpc/server.h"
#include "bitcoin/src/psbt.h"
#include "bitcoin/src/span.h"
#include "bitcoin/src/streams.h"
#include "bitcoin/src/test/fuzz/FuzzedDataProvider.h"
#include "bitcoin/src/test/fuzz/fuzz.h"
#include "bitcoin/src/test/fuzz/util.h"
#include "bitcoin/src/test/util/setup_common.h"
#include "bitcoin/src/tinyformat.h"
#include "bitcoin/src/uint256.h"
#include "bitcoin/src/univalue/include/univalue.h"
#include "bitcoin/src/util/strencodings.h"
#include "bitcoin/src/util/string.h"
#include "bitcoin/src/util/time.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>
enum class ChainType;

using util::Join;
using util::ToString;

extern "C" int go_btcd_rpc(char* cargs, int len);

namespace {
struct RPCFuzzTestingSetup : public TestingSetup {

    RPCFuzzTestingSetup(const ChainType chain_type, TestOpts opts) : TestingSetup{chain_type, opts}
    {
    }

    int CallRPC(const JSONRPCRequest& request)
    {
        auto ret = JSONRPCExec(request, true);

        if (ret.write().find("unknown") != std::string::npos)
            return 1;

        if (ret["error"].isNull())
            return 0;

        if (ret["error"]["code"].getInt<int64_t>() == -1)
            return -1;

        return 1;
    }

    int CallRPCBtcd(const JSONRPCRequest& request)
    {
        const auto& str = JSONRPCRequestObj(request.strMethod, request.params, 0).write();
        return go_btcd_rpc((char*)str.c_str(), str.size());
    }

    JSONRPCRequest GenerateRequest(const std::string& rpc_method, const std::vector<std::string>& arguments)
    {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = rpc_method;
        request.params = RPCConvertValues(rpc_method, arguments);

        return request;
    }

    std::vector<std::string> GetRPCCommands() const
    {
        return tableRPC.listCommands();
    }
};

RPCFuzzTestingSetup* rpc_testing_setup = nullptr;
std::string g_limit_to_rpc_command;
std::unique_ptr<RPCFuzzTestingSetup> setup;

// RPC commands which are not appropriate for fuzzing: such as RPC commands
// reading or writing to a filename passed as an RPC parameter, RPC commands
// resulting in network activity, etc.
const std::vector<std::string> RPC_COMMANDS_NOT_SAFE_FOR_FUZZING{
    "addconnection",  // avoid DNS lookups
    "addnode",        // avoid DNS lookups
    "addpeeraddress", // avoid DNS lookups
    "dumptxoutset",   // avoid writing to disk
    "dumpwallet", // avoid writing to disk
    "enumeratesigners",
    "echoipc",              // avoid assertion failure (Assertion `"EnsureAnyNodeContext(request.context).init" && check' failed.)
    "generatetoaddress",    // avoid prohibitively slow execution (when `num_blocks` is large)
    "generatetodescriptor", // avoid prohibitively slow execution (when `nblocks` is large)
    "gettxoutproof",        // avoid prohibitively slow execution
    "importmempool", // avoid reading from disk
    "importwallet", // avoid reading from disk
    "loadtxoutset",   // avoid reading from disk
    "loadwallet",   // avoid reading from disk
    "savemempool",           // disabled as a precautionary measure: may take a file path argument in the future
    "setban",                // avoid DNS lookups
    "stop",                  // avoid shutdown state
};

// RPC commands which are safe for fuzzing.
const std::vector<std::string> RPC_COMMANDS_SAFE_FOR_FUZZING{
    "help",
    "analyzepsbt",
    "clearbanned",
    "combinepsbt",
    "combinerawtransaction",
    "converttopsbt",
    "createmultisig",
    "createpsbt",
    "createrawtransaction",
    "decodepsbt",
    "decoderawtransaction",
    "decodescript",
    "deriveaddresses",
    "descriptorprocesspsbt",
    "disconnectnode",
    "echo",
    "echojson",
    "estimaterawfee",
    "estimatesmartfee",
    "finalizepsbt",
    "generate",
    "generateblock",
    "getaddednodeinfo",
    "getaddrmaninfo",
    "getbestblockhash",
    "getblock",
    "getblockchaininfo",
    "getblockcount",
    "getblockfilter",
    "getblockfrompeer", // when no peers are connected, no p2p message is sent
    "getblockhash",
    "getblockheader",
    "getblockstats",
    "getblocktemplate",
    "getchaintips",
    "getchainstates",
    "getchaintxstats",
    "getconnectioncount",
    "getdeploymentinfo",
    "getdescriptorinfo",
    "getdifficulty",
    "getindexinfo",
    "getmemoryinfo",
    "getmempoolancestors",
    "getmempooldescendants",
    "getmempoolentry",
    "getmempoolinfo",
    "getmininginfo",
    "getnettotals",
    "getnetworkhashps",
    "getnetworkinfo",
    "getnodeaddresses",
    "getpeerinfo",
    "getprioritisedtransactions",
    "getrawaddrman",
    "getrawmempool",
    "getrawtransaction",
    "getrpcinfo",
    "gettxout",
    "gettxoutsetinfo",
    "gettxspendingprevout",
    "invalidateblock",
    "joinpsbts",
    "listbanned",
    "logging",
    "mockscheduler",
    "ping",
    "preciousblock",
    "prioritisetransaction",
    "pruneblockchain",
    "reconsiderblock",
    "scanblocks",
    "scantxoutset",
    "sendmsgtopeer", // when no peers are connected, no p2p message is sent
    "sendrawtransaction",
    "setmocktime",
    "setnetworkactive",
    "signmessagewithprivkey",
    "signrawtransactionwithkey",
    "submitblock",
    "submitheader",
    "submitpackage",
    "syncwithvalidationinterfacequeue",
    "testmempoolaccept",
    "uptime",
    "utxoupdatepsbt",
    "validateaddress",
    "verifychain",
    "verifymessage",
    "verifytxoutproof",
    "waitforblock",
    "waitforblockheight",
    "waitfornewblock",
};

std::string ConsumeScalarRPCArgument(FuzzedDataProvider& fuzzed_data_provider, bool& good_data)
{
    const size_t max_string_length = 4096;
    const size_t max_base58_bytes_length{64};
    std::string r;
    CallOneOf(
        fuzzed_data_provider,
        [&] {
            // string argument
            r = fuzzed_data_provider.ConsumeRandomLengthString(max_string_length);
        },
        [&] {
            // base64 argument
            r = EncodeBase64(fuzzed_data_provider.ConsumeRandomLengthString(max_string_length));
        },
        [&] {
            // hex argument
            r = HexStr(fuzzed_data_provider.ConsumeRandomLengthString(max_string_length));
        },
        [&] {
            // bool argument
            r = fuzzed_data_provider.ConsumeBool() ? "true" : "false";
        },
        [&] {
            // range argument
            r = "[" + ToString(fuzzed_data_provider.ConsumeIntegral<int64_t>()) + "," + ToString(fuzzed_data_provider.ConsumeIntegral<int64_t>()) + "]";
        },
        [&] {
            // integral argument (int64_t)
            r = ToString(fuzzed_data_provider.ConsumeIntegral<int64_t>());
        },
        [&] {
            // integral argument (uint64_t)
            r = ToString(fuzzed_data_provider.ConsumeIntegral<uint64_t>());
        },
        [&] {
            // floating point argument
            r = strprintf("%f", fuzzed_data_provider.ConsumeFloatingPoint<double>());
        },
        [&] {
            // tx destination argument
            r = EncodeDestination(ConsumeTxDestination(fuzzed_data_provider));
        },
        [&] {
            // uint160 argument
            r = ConsumeUInt160(fuzzed_data_provider).ToString();
        },
        [&] {
            // uint256 argument
            r = ConsumeUInt256(fuzzed_data_provider).ToString();
        },
        [&] {
            // base32 argument
            r = EncodeBase32(fuzzed_data_provider.ConsumeRandomLengthString(max_string_length));
        },
        [&] {
            // base58 argument
            r = EncodeBase58(MakeUCharSpan(fuzzed_data_provider.ConsumeRandomLengthString(max_base58_bytes_length)));
        },
        [&] {
            // base58 argument with checksum
            r = EncodeBase58Check(MakeUCharSpan(fuzzed_data_provider.ConsumeRandomLengthString(max_base58_bytes_length)));
        },
        [&] {
            // hex encoded block
            std::optional<CBlock> opt_block = ConsumeDeserializable<CBlock>(fuzzed_data_provider, TX_WITH_WITNESS);
            if (!opt_block) {
                good_data = false;
                return;
            }
            DataStream data_stream{};
            data_stream << TX_WITH_WITNESS(*opt_block);
            r = HexStr(data_stream);
        },
        [&] {
            // hex encoded block header
            std::optional<CBlockHeader> opt_block_header = ConsumeDeserializable<CBlockHeader>(fuzzed_data_provider);
            if (!opt_block_header) {
                good_data = false;
                return;
            }
            DataStream data_stream{};
            data_stream << *opt_block_header;
            r = HexStr(data_stream);
        },
        [&] {
            // hex encoded tx
            std::optional<CMutableTransaction> opt_tx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider, TX_WITH_WITNESS);
            if (!opt_tx) {
                good_data = false;
                return;
            }
            DataStream data_stream;
            auto allow_witness = (fuzzed_data_provider.ConsumeBool() ? TX_WITH_WITNESS : TX_NO_WITNESS);
            data_stream << allow_witness(*opt_tx);
            r = HexStr(data_stream);
        },
        [&] {
            // base64 encoded psbt
            std::optional<PartiallySignedTransaction> opt_psbt = ConsumeDeserializable<PartiallySignedTransaction>(fuzzed_data_provider);
            if (!opt_psbt) {
                good_data = false;
                return;
            }
            DataStream data_stream{};
            data_stream << *opt_psbt;
            r = EncodeBase64(data_stream);
        },
        [&] {
            // base58 encoded key
            CKey key = ConsumePrivateKey(fuzzed_data_provider);
            if (!key.IsValid()) {
                good_data = false;
                return;
            }
            r = EncodeSecret(key);
        },
        [&] {
            // hex encoded pubkey
            CKey key = ConsumePrivateKey(fuzzed_data_provider);
            if (!key.IsValid()) {
                good_data = false;
                return;
            }
            r = HexStr(key.GetPubKey());
        });
    return r;
}

std::string ConsumeArrayRPCArgument(FuzzedDataProvider& fuzzed_data_provider, bool& good_data)
{
    std::vector<std::string> scalar_arguments;
    LIMITED_WHILE(good_data && fuzzed_data_provider.ConsumeBool(), 100)
    {
        scalar_arguments.push_back(ConsumeScalarRPCArgument(fuzzed_data_provider, good_data));
    }
    return "[\"" + Join(scalar_arguments, "\",\"") + "\"]";
}

std::string ConsumeRPCArgument(FuzzedDataProvider& fuzzed_data_provider, bool& good_data)
{
    return fuzzed_data_provider.ConsumeBool() ? ConsumeScalarRPCArgument(fuzzed_data_provider, good_data) : ConsumeArrayRPCArgument(fuzzed_data_provider, good_data);
}

RPCFuzzTestingSetup* InitializeRPCFuzzTestingSetup()
{
    setup = MakeNoLogFileContext<RPCFuzzTestingSetup>();
    return setup.get();
}
}; // namespace

void check_btcd()
{
    JSONRPCRequest req = rpc_testing_setup->GenerateRequest("help", {""});
    int err = rpc_testing_setup->CallRPCBtcd(req);
    if (err == -2) {
        std::cerr << "Error: Could not connect to the BTCD server \n";
        std::cerr << "Please start the btcd server by executing:\n";
        std::cerr << "   btcd --connect=127.0.0.1 -P bitcoinfuzz -u bitcoinfuzz --notls\n";
        std::terminate();
    } else if (err == 401) { // Unauthorized
        std::cerr << "Error: BTCD server has been started with an unexpected username / password combo.\n";
        std::cerr << "Please ensure that both the username and password are: bitcoinfuzz\n";
        std::terminate();
    }
}

void initialize_rpc()
{
    rpc_testing_setup = InitializeRPCFuzzTestingSetup();
    SetRPCWarmupFinished();
    const std::vector<std::string> supported_rpc_commands = rpc_testing_setup->GetRPCCommands();
    for (const std::string& rpc_command : supported_rpc_commands) {
        const bool safe_for_fuzzing = std::find(RPC_COMMANDS_SAFE_FOR_FUZZING.begin(), RPC_COMMANDS_SAFE_FOR_FUZZING.end(), rpc_command) != RPC_COMMANDS_SAFE_FOR_FUZZING.end();
        const bool not_safe_for_fuzzing = std::find(RPC_COMMANDS_NOT_SAFE_FOR_FUZZING.begin(), RPC_COMMANDS_NOT_SAFE_FOR_FUZZING.end(), rpc_command) != RPC_COMMANDS_NOT_SAFE_FOR_FUZZING.end();
        if (!(safe_for_fuzzing || not_safe_for_fuzzing)) {
            std::cerr << "Error: RPC command \"" << rpc_command << "\" not found in RPC_COMMANDS_SAFE_FOR_FUZZING or RPC_COMMANDS_NOT_SAFE_FOR_FUZZING. Please update " << __FILE__ << ".\n";
            std::terminate();
        }
        if (safe_for_fuzzing && not_safe_for_fuzzing) {
            std::cerr << "Error: RPC command \"" << rpc_command << "\" found in *both* RPC_COMMANDS_SAFE_FOR_FUZZING and RPC_COMMANDS_NOT_SAFE_FOR_FUZZING. Please update " << __FILE__ << ".\n";
            std::terminate();
        }
    }
    const char* limit_to_rpc_command_env = std::getenv("LIMIT_TO_RPC_COMMAND");
    if (limit_to_rpc_command_env != nullptr) {
        g_limit_to_rpc_command = std::string{limit_to_rpc_command_env};
    }

    check_btcd();
}

FUZZ_TARGET(rpc, .init = initialize_rpc)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    bool good_data{true};
    SetMockTime(ConsumeTime(fuzzed_data_provider));

    const std::string rpc_command = fuzzed_data_provider.ConsumeRandomLengthString(64);
    if (!g_limit_to_rpc_command.empty() && rpc_command != g_limit_to_rpc_command) {
        return;
    }

    const bool safe_for_fuzzing = std::find(RPC_COMMANDS_SAFE_FOR_FUZZING.begin(), RPC_COMMANDS_SAFE_FOR_FUZZING.end(), rpc_command) != RPC_COMMANDS_SAFE_FOR_FUZZING.end();
    if (!safe_for_fuzzing) {
        return;
    }

    std::vector<std::string> arguments;
    LIMITED_WHILE(good_data && fuzzed_data_provider.ConsumeBool(), 100)
    {
        arguments.push_back(ConsumeRPCArgument(fuzzed_data_provider, good_data));
    }

    JSONRPCRequest req;
    int btcd_err{0}, core_err{0}; 

    try {
        req = rpc_testing_setup->GenerateRequest(rpc_command, arguments);
    } catch (const std::runtime_error& ) {
        return;
    }

    btcd_err = rpc_testing_setup->CallRPCBtcd(req);
    core_err = rpc_testing_setup->CallRPC(req);

    if (btcd_err == -1 || core_err == -1)
        return;

    if (btcd_err != core_err) {
        setup.reset(); // CRITICAL: Without this, your tmp/ directory will blow up.
    }

    assert(btcd_err == core_err);
}
