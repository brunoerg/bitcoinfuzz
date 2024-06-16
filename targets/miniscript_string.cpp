#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <iostream>
#include <script/miniscript.h>

#include "miniscript_string.h"
#include "../bitcoin/src/pubkey.h"
#include "../bitcoin/src/key.h"

extern "C" bool rust_miniscript_from_str(const char* miniscript_str);
extern "C" char* rust_miniscript_from_str_check_key(const char* miniscript_str);

using Fragment = miniscript::Fragment;
using NodeRef = miniscript::NodeRef<CPubKey>;
using Node = miniscript::Node<CPubKey>;
using Type = miniscript::Type;
using MsCtx = miniscript::MiniscriptContext;
using miniscript::operator"" _mst;

/** TestData groups various kinds of precomputed data necessary in this test. */
struct TestData {
    //! The only public keys used in this test.
    std::vector<CPubKey> pubkeys;
    //! A map from the public keys to their CKeyIDs (faster than hashing every time).
    std::map<CPubKey, CKeyID> pkhashes;
    std::map<CKeyID, CPubKey> pkmap;
    std::map<XOnlyPubKey, CKeyID> xonly_pkhashes;
    std::map<CPubKey, std::vector<unsigned char>> signatures;
    std::map<XOnlyPubKey, std::vector<unsigned char>> schnorr_signatures;

    // Various precomputed hashes
    std::vector<std::vector<unsigned char>> sha256;
    std::vector<std::vector<unsigned char>> ripemd160;
    std::vector<std::vector<unsigned char>> hash256;
    std::vector<std::vector<unsigned char>> hash160;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> sha256_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> ripemd160_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> hash256_preimages;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> hash160_preimages;

    TestData()
    {
        static ECC_Context ctx;
        // All our signatures sign (and are required to sign) this constant message.
        auto const MESSAGE_HASH = uint256S("f5cd94e18b6fe77dd7aca9e35c2b0c9cbd86356c80a71065");
        // We don't pass additional randomness when creating a schnorr signature.
        auto const EMPTY_AUX{uint256S("")};

        // We generate 255 public keys and 255 hashes of each type.
        for (int i = 1; i <= 255; ++i) {
            // This 32-byte array functions as both private key data and hash preimage (31 zero bytes plus any nonzero byte).
            unsigned char keydata[32] = {0};
            keydata[31] = i;

            // Compute CPubkey and CKeyID
            CKey key;
            key.Set(keydata, keydata + 32, true);
            CPubKey pubkey = key.GetPubKey();
            CKeyID keyid = pubkey.GetID();
            pubkeys.push_back(pubkey);
            pkhashes.emplace(pubkey, keyid);
            pkmap.emplace(keyid, pubkey);
            XOnlyPubKey xonly_pubkey{pubkey};
            uint160 xonly_hash{Hash160(xonly_pubkey)};
            xonly_pkhashes.emplace(xonly_pubkey, xonly_hash);
            pkmap.emplace(xonly_hash, pubkey);

            // Compute ECDSA signatures on MESSAGE_HASH with the private keys.
            std::vector<unsigned char> sig, schnorr_sig(64);
            assert(key.Sign(MESSAGE_HASH, sig));
            sig.push_back(1); // sighash byte
            signatures.emplace(pubkey, sig);
            assert(key.SignSchnorr(MESSAGE_HASH, schnorr_sig, nullptr, EMPTY_AUX));
            schnorr_sig.push_back(1); // Maximally sized Schnorr sigs have a sighash byte.
            schnorr_signatures.emplace(XOnlyPubKey{pubkey}, schnorr_sig);

            // Compute various hashes
            std::vector<unsigned char> hash;
            hash.resize(32);
            CSHA256().Write(keydata, 32).Finalize(hash.data());
            sha256.push_back(hash);
            sha256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash256().Write(keydata).Finalize(hash);
            hash256.push_back(hash);
            hash256_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            hash.resize(20);
            CRIPEMD160().Write(keydata, 32).Finalize(hash.data());
            ripemd160.push_back(hash);
            ripemd160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
            CHash160().Write(keydata).Finalize(hash);
            hash160.push_back(hash);
            hash160_preimages[hash] = std::vector<unsigned char>(keydata, keydata + 32);
        }
    }
};

//! Global TestData object
std::unique_ptr<const TestData> g_testdata(new TestData());

struct KeyConverter {
    typedef CPubKey Key;

    const miniscript::MiniscriptContext m_script_ctx;

    constexpr KeyConverter(miniscript::MiniscriptContext ctx) noexcept : m_script_ctx{ctx} {}

    bool KeyCompare(const Key& a, const Key& b) const {
        return a < b;
    }

    //! Convert a public key to bytes.
    std::vector<unsigned char> ToPKBytes(const CPubKey& key) const {
        if (!miniscript::IsTapscript(m_script_ctx)) {
            return {key.begin(), key.end()};
        }
        const XOnlyPubKey xonly_pubkey{key};
        return {xonly_pubkey.begin(), xonly_pubkey.end()};
    }

    //! Convert a public key to its Hash160 bytes (precomputed).
    std::vector<unsigned char> ToPKHBytes(const CPubKey& key) const {
        if (!miniscript::IsTapscript(m_script_ctx)) {
            auto hash = g_testdata->pkhashes.at(key);
            return {hash.begin(), hash.end()};
        }
        const XOnlyPubKey xonly_key{key};
        auto hash = g_testdata->xonly_pkhashes.at(xonly_key);
        return {hash.begin(), hash.end()};
    }

    //! Parse a public key from a range of hex characters.
    template<typename I>
    std::optional<Key> FromString(I first, I last) const {
        auto bytes = ParseHex(std::string(first, last));
        Key key{bytes.begin(), bytes.end()};
        if (key.IsValid()) return key;
        return {};
    }

    template<typename I>
    std::optional<Key> FromPKBytes(I first, I last) const {
        if (!miniscript::IsTapscript(m_script_ctx)) {
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
        return g_testdata->pkmap.at(keyid);
    }

    std::optional<std::string> ToString(const Key& key) const {
        return HexStr(ToPKBytes(key));
    }

    miniscript::MiniscriptContext MsContext() const {
        return m_script_ctx;
    }
};

bool BitcoinCoreString(const std::string& input_str)
{
    KeyConverter parser_ctx{miniscript::MiniscriptContext::P2WSH};
    auto ret{miniscript::FromString(input_str, parser_ctx)};
    if (ret && ret->IsSane()) {
        return true;
    }

    KeyConverter parser_ctx_tap{miniscript::MiniscriptContext::TAPSCRIPT};
    ret = miniscript::FromString(input_str, parser_ctx_tap);
    if (ret && ret->IsSane()) {
        return true;
    }

    return false;
}

void MiniscriptFromString(FuzzedDataProvider& provider) 
{
    std::string input_str{provider.ConsumeRemainingBytesAsString().c_str()};
    const bool core{BitcoinCoreString(input_str)};
    const std::string rust_miniscript{rust_miniscript_from_str_check_key(input_str.c_str())};
    if (rust_miniscript.find("maxrecursive") != std::string::npos) return;
    if (core) assert(rust_miniscript == "1");
    else assert(rust_miniscript == "0");
}

