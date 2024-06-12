#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <script/miniscript.h>

#include "miniscript_string.h"
#include "../bitcoin/pubkey.h"
#include "../bitcoin/key.h"

extern "C" bool rust_miniscript_from_str(const char* miniscript_str);

using Fragment = miniscript::Fragment;
using NodeRef = miniscript::NodeRef<CPubKey>;
using Node = miniscript::Node<CPubKey>;
using Type = miniscript::Type;
using MsCtx = miniscript::MiniscriptContext;
using miniscript::operator"" _mst;

//! Some pre-computed data for more efficient string roundtrips and to simulate challenges.
struct TestData {
    typedef CPubKey Key;

    // Precomputed public keys, and a dummy signature for each of them.
    std::vector<Key> dummy_keys;
    std::map<Key, int> dummy_key_idx_map;
    std::map<CKeyID, Key> dummy_keys_map;
    std::map<Key, std::pair<std::vector<unsigned char>, bool>> dummy_sigs;
    std::map<XOnlyPubKey, std::pair<std::vector<unsigned char>, bool>> schnorr_sigs;

    // Precomputed hashes of each kind.
    std::vector<std::vector<unsigned char>> sha256;
    std::vector<std::vector<unsigned char>> ripemd160;
    std::vector<std::vector<unsigned char>> hash256;
    std::vector<std::vector<unsigned char>> hash160;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> sha256_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> ripemd160_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> hash256_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> hash160_preimages;

    //! Set the precomputed data.
    void Init() {
        unsigned char keydata[32] = {1};
        // All our signatures sign (and are required to sign) this constant message.
        auto const MESSAGE_HASH{uint256S("f5cd94e18b6fe77dd7aca9e35c2b0c9cbd86356c80a71065")};
        // We don't pass additional randomness when creating a schnorr signature.
        auto const EMPTY_AUX{uint256S("")};

        for (size_t i = 0; i < 256; i++) {
            keydata[31] = i;
            CKey privkey;
            privkey.Set(keydata, keydata + 32, true);
            const Key pubkey = privkey.GetPubKey();

            dummy_keys.push_back(pubkey);
            dummy_key_idx_map.emplace(pubkey, i);
            dummy_keys_map.insert({pubkey.GetID(), pubkey});
            XOnlyPubKey xonly_pubkey{pubkey};
            dummy_key_idx_map.emplace(xonly_pubkey, i);
            uint160 xonly_hash{Hash160(xonly_pubkey)};
            dummy_keys_map.emplace(xonly_hash, pubkey);

            std::vector<unsigned char> sig, schnorr_sig(64);
            privkey.Sign(MESSAGE_HASH, sig);
            sig.push_back(1); // SIGHASH_ALL
            dummy_sigs.insert({pubkey, {sig, i & 1}});
            assert(privkey.SignSchnorr(MESSAGE_HASH, schnorr_sig, nullptr, EMPTY_AUX));
            schnorr_sig.push_back(1); // Maximally-sized signature has sighash byte
            schnorr_sigs.emplace(XOnlyPubKey{pubkey}, std::make_pair(std::move(schnorr_sig), i & 1));

            std::vector<unsigned char> hash;
            hash.resize(32);
            CSHA256().Write(keydata, 32).Finalize(hash.data());
            sha256.push_back(hash);
            if (i & 1) sha256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash256().Write(keydata).Finalize(hash);
            hash256.push_back(hash);
            if (i & 1) hash256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            hash.resize(20);
            CRIPEMD160().Write(keydata, 32).Finalize(hash.data());
            assert(hash.size() == 20);
            ripemd160.push_back(hash);
            if (i & 1) ripemd160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash160().Write(keydata).Finalize(hash);
            hash160.push_back(hash);
            if (i & 1) hash160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
        }
    }

    //! Get the (Schnorr or ECDSA, depending on context) signature for this pubkey.
    const std::pair<std::vector<unsigned char>, bool>* GetSig(const MsCtx script_ctx, const Key& key) const {
        if (!miniscript::IsTapscript(script_ctx)) {
            const auto it = dummy_sigs.find(key);
            if (it == dummy_sigs.end()) return nullptr;
            return &it->second;
        } else {
            const auto it = schnorr_sigs.find(XOnlyPubKey{key});
            if (it == schnorr_sigs.end()) return nullptr;
            return &it->second;
        }
    }
} TEST_DATA;

/**
 * Context to parse a Miniscript node to and from Script or text representation.
 * Uses an integer (an index in the dummy keys array from the test data) as keys in order
 * to focus on fuzzing the Miniscript nodes' test representation, not the key representation.
 */
struct ParserContext {
    typedef CPubKey Key;

    const MsCtx script_ctx;

    constexpr ParserContext(MsCtx ctx) noexcept : script_ctx(ctx) {}

    bool KeyCompare(const Key& a, const Key& b) const {
        return a < b;
    }

    std::optional<std::string> ToString(const Key& key) const
    {
        auto it = TEST_DATA.dummy_key_idx_map.find(key);
        if (it == TEST_DATA.dummy_key_idx_map.end()) return {};
        uint8_t idx = it->second;
        return HexStr(Span{&idx, 1});
    }

    std::vector<unsigned char> ToPKBytes(const Key& key) const {
        if (!miniscript::IsTapscript(script_ctx)) {
            return {key.begin(), key.end()};
        }
        const XOnlyPubKey xonly_pubkey{key};
        return {xonly_pubkey.begin(), xonly_pubkey.end()};
    }

    std::vector<unsigned char> ToPKHBytes(const Key& key) const {
        if (!miniscript::IsTapscript(script_ctx)) {
            const auto h = Hash160(key);
            return {h.begin(), h.end()};
        }
        const auto h = Hash160(XOnlyPubKey{key});
        return {h.begin(), h.end()};
    }

    template<typename I>
    std::optional<Key> FromString(I first, I last) const {
        if (last - first != 2) return {};
        auto idx = ParseHex(std::string(first, last));
        if (idx.size() != 1) return {};
        return TEST_DATA.dummy_keys[idx[0]];
    }

    template<typename I>
    std::optional<Key> FromPKBytes(I first, I last) const {
        if (!miniscript::IsTapscript(script_ctx)) {
            Key key{first, last};
            if (key.IsValid()) return key;
            return {};
        }
        if (last - first != 32) return {};
        XOnlyPubKey xonly_pubkey;
        std::copy(first, last, xonly_pubkey.begin());
        return xonly_pubkey.GetEvenCorrespondingCPubKey();
    }

    template<typename I>
    std::optional<Key> FromPKHBytes(I first, I last) const {
        assert(last - first == 20);
        CKeyID keyid;
        std::copy(first, last, keyid.begin());
        const auto it = TEST_DATA.dummy_keys_map.find(keyid);
        if (it == TEST_DATA.dummy_keys_map.end()) return {};
        return it->second;
    }

    MsCtx MsContext() const {
        return script_ctx;
    }
};

bool BitcoinCoreString(const std::string& input_str)
{
    ParserContext parser_ctx{miniscript::MiniscriptContext::P2WSH};
    auto ret{miniscript::FromString(input_str, parser_ctx)};
    if (ret && ret->IsSane()) return true;

    ParserContext parser_ctx_tap{miniscript::MiniscriptContext::TAPSCRIPT};
    ret = miniscript::FromString(input_str, parser_ctx_tap);
    if (ret && ret->IsSane()) return true;

    return false;
}

void MiniscriptFromString(FuzzedDataProvider& provider) 
{
    std::string input_str{provider.ConsumeRemainingBytesAsString().c_str()};
    const bool core{BitcoinCoreString(input_str)};
    const bool rust_miniscript{rust_miniscript_from_str(input_str.c_str())};
    assert(core == rust_miniscript);
}

