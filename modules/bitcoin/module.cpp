#include <algorithm>
#include <optional>
#include <span>
#include <string>

#include "util/translation.h"
const TranslateFn G_TRANSLATION_FUN{nullptr};

#include "base58.h"
#include "blockencodings.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/tx_check.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "crypto/aes.h"
#include "descriptor.h"
#include "key.h"
#include "key_io.h"
#include "module.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "psbt.h"
#include "script/interpreter.h"
#include "script/miniscript.h"
#include "script/script.h"
#include "secp256k1.h"
#include "span.h"
#include "streams.h"
#include "util/bip32.h"
#include "util/chaintype.h"
#include "validation.h"

namespace {
class FuzzedSignatureChecker : public BaseSignatureChecker {
public:
  bool CheckECDSASignature(const std::vector<unsigned char> &scriptSig,
                           const std::vector<unsigned char> &vchPubKey,
                           const CScript &scriptCode,
                           SigVersion sigversion) const override {
    return true;
  }

  bool CheckSchnorrSignature(std::span<const unsigned char> sig,
                             std::span<const unsigned char> pubkey,
                             SigVersion sigversion,
                             ScriptExecutionData &execdata,
                             ScriptError *serror = nullptr) const override {
    return true;
  }

  bool CheckLockTime(const CScriptNum &nLockTime) const override {
    return true;
  }

  bool CheckSequence(const CScriptNum &nSequence) const override {
    return true;
  }

  virtual ~FuzzedSignatureChecker() = default;
};
} // namespace

namespace bitcoinfuzz {
namespace module {
Bitcoin::Bitcoin(void) : BaseModule("Bitcoin") {}

using Fragment = miniscript::Fragment;
using Node = miniscript::Node<CPubKey>;
using Type = miniscript::Type;
using MsCtx = miniscript::MiniscriptContext;
using miniscript::operator"" _mst;

//! Some pre-computed data for more efficient string roundtrips and to simulate
//! challenges.
struct TestData {
  typedef CPubKey Key;

  // Precomputed public keys, and a dummy signature for each of them.
  std::vector<Key> dummy_keys;
  std::map<Key, int> dummy_key_idx_map;
  std::map<CKeyID, Key> dummy_keys_map;
  std::map<Key, std::pair<std::vector<unsigned char>, bool>> dummy_sigs;
  std::map<XOnlyPubKey, std::pair<std::vector<unsigned char>, bool>>
      schnorr_sigs;

  // Precomputed hashes of each kind.
  std::vector<std::vector<unsigned char>> sha256;
  std::vector<std::vector<unsigned char>> ripemd160;
  std::vector<std::vector<unsigned char>> hash256;
  std::vector<std::vector<unsigned char>> hash160;
  std::map<std::vector<unsigned char>, std::vector<unsigned char>>
      sha256_preimages;
  std::map<std::vector<unsigned char>, std::vector<unsigned char>>
      ripemd160_preimages;
  std::map<std::vector<unsigned char>, std::vector<unsigned char>>
      hash256_preimages;
  std::map<std::vector<unsigned char>, std::vector<unsigned char>>
      hash160_preimages;

  //! Set the precomputed data.
  void Init() {
    unsigned char keydata[32] = {1};
    // All our signatures sign (and are required to sign) this constant message.
    constexpr uint256 MESSAGE_HASH{
        "0000000000000000f5cd94e18b6fe77dd7aca9e35c2b0c9cbd86356c80a71065"};
    // We don't pass additional randomness when creating a schnorr signature.
    const auto EMPTY_AUX{uint256::ZERO};

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
      assert(
          privkey.SignSchnorr(MESSAGE_HASH, schnorr_sig, nullptr, EMPTY_AUX));
      schnorr_sig.push_back(1); // Maximally-sized signature has sighash byte
      schnorr_sigs.emplace(XOnlyPubKey{pubkey},
                           std::make_pair(std::move(schnorr_sig), i & 1));

      std::vector<unsigned char> hash;
      hash.resize(32);
      CSHA256().Write(keydata, 32).Finalize(hash.data());
      sha256.push_back(hash);
      if (i & 1)
        sha256_preimages[hash] =
            std::vector<unsigned char>(keydata, keydata + 32);
      CHash256().Write(keydata).Finalize(hash);
      hash256.push_back(hash);
      if (i & 1)
        hash256_preimages[hash] =
            std::vector<unsigned char>(keydata, keydata + 32);
      hash.resize(20);
      CRIPEMD160().Write(keydata, 32).Finalize(hash.data());
      assert(hash.size() == 20);
      ripemd160.push_back(hash);
      if (i & 1)
        ripemd160_preimages[hash] =
            std::vector<unsigned char>(keydata, keydata + 32);
      CHash160().Write(keydata).Finalize(hash);
      hash160.push_back(hash);
      if (i & 1)
        hash160_preimages[hash] =
            std::vector<unsigned char>(keydata, keydata + 32);
    }
  }

  //! Get the (Schnorr or ECDSA, depending on context) signature for this
  //! pubkey.
  const std::pair<std::vector<unsigned char>, bool> *
  GetSig(const MsCtx script_ctx, const Key &key) const {
    if (!miniscript::IsTapscript(script_ctx)) {
      const auto it = dummy_sigs.find(key);
      if (it == dummy_sigs.end())
        return nullptr;
      return &it->second;
    } else {
      const auto it = schnorr_sigs.find(XOnlyPubKey{key});
      if (it == schnorr_sigs.end())
        return nullptr;
      return &it->second;
    }
  }
} TEST_DATA;

/**
 * Context to parse a Miniscript node to and from Script or text representation.
 * Uses an integer (an index in the dummy keys array from the test data) as keys
 * in order to focus on fuzzing the Miniscript nodes' test representation, not
 * the key representation.
 */
struct ParserContext {
  typedef CPubKey Key;

  const MsCtx script_ctx;

  constexpr ParserContext(MsCtx ctx) noexcept : script_ctx(ctx) {}

  bool KeyCompare(const Key &a, const Key &b) const { return a < b; }

  std::optional<std::string> ToString(const Key &key) const {
    auto it = TEST_DATA.dummy_key_idx_map.find(key);
    if (it == TEST_DATA.dummy_key_idx_map.end())
      return {};
    uint8_t idx = it->second;
    return HexStr(std::span{&idx, 1});
  }

  std::vector<unsigned char> ToPKBytes(const Key &key) const {
    if (!miniscript::IsTapscript(script_ctx)) {
      return {key.begin(), key.end()};
    }
    const XOnlyPubKey xonly_pubkey{key};
    return {xonly_pubkey.begin(), xonly_pubkey.end()};
  }

  std::vector<unsigned char> ToPKHBytes(const Key &key) const {
    if (!miniscript::IsTapscript(script_ctx)) {
      const auto h = Hash160(key);
      return {h.begin(), h.end()};
    }
    const auto h = Hash160(XOnlyPubKey{key});
    return {h.begin(), h.end()};
  }

  std::optional<Key> FromString(std::span<const char> &in) const {
    if (in.size() != 1 && in.size() != 2)
      return {};
    std::string key_str(in.begin(), in.end());
    // Normalize symbolic one-digit key indexes (e.g. pk(8) -> pk(08))
    // so they match Core's pre-generated dummy key table representation.
    if (key_str.size() == 1) {
      key_str.insert(key_str.begin(), '0');
    }
    auto idx = ParseHex(key_str);
    if (idx.size() != 1)
      return {};
    return TEST_DATA.dummy_keys[idx[0]];
  }

  template <typename I> std::optional<Key> FromString(I first, I last) const {
    if (last - first != 1 && last - first != 2)
      return {};
    std::string key_str(first, last);
    if (key_str.size() == 1) {
      key_str.insert(key_str.begin(), '0');
    }
    auto idx = ParseHex(key_str);
    if (idx.size() != 1)
      return {};
    return TEST_DATA.dummy_keys[idx[0]];
  }

  template <typename I> std::optional<Key> FromPKBytes(I first, I last) const {
    if (!miniscript::IsTapscript(script_ctx)) {
      Key key{first, last};
      if (key.IsValid())
        return key;
      return {};
    }
    if (last - first != 32)
      return {};
    XOnlyPubKey xonly_pubkey;
    std::copy(first, last, xonly_pubkey.begin());
    return xonly_pubkey.GetEvenCorrespondingCPubKey();
  }

  template <typename I> std::optional<Key> FromPKHBytes(I first, I last) const {
    assert(last - first == 20);
    CKeyID keyid;
    std::copy(first, last, keyid.begin());
    const auto it = TEST_DATA.dummy_keys_map.find(keyid);
    if (it == TEST_DATA.dummy_keys_map.end())
      return {};
    return it->second;
  }

  MsCtx MsContext() const { return script_ctx; }
};

std::optional<std::string>
Bitcoin::script_parse(std::span<const uint8_t> buffer) const {
  DataStream ds{buffer};
  CScript script;
  try {
    ds >> script;
  } catch (const std::ios_base::failure &e) {
    return "0";
  }
  if (script.IsUnspendable())
    return "0";
  int version;
  std::vector<uint8_t> program;
  auto final_res{std::to_string(script.GetSigOpCount(false))};
  final_res += script.IsWitnessProgram(version, program) ? "1" : "0";
  final_res += script.IsPushOnly() ? "1" : "0";
  return final_res;
}

std::optional<bool> Bitcoin::script_eval(const std::vector<uint8_t> &input_data,
                                         unsigned int flags,
                                         size_t version) const {
  CScript script(input_data.begin(), input_data.end());
  if (script.empty())
    return std::nullopt;

  std::vector<std::vector<unsigned char>> stack;
  SigVersion sig_version =
      (version == 0) ? SigVersion::BASE : SigVersion::WITNESS_V0;

  return EvalScript(stack, script, 0, FuzzedSignatureChecker(), sig_version,
                    nullptr);
}

std::optional<bool>
Bitcoin::verify_script(const std::vector<uint8_t> &script_sig,
                       const std::vector<uint8_t> &script_pubkey) const {
  CScript ssig(script_sig.begin(), script_sig.end());
  if (ssig.empty())
    return std::nullopt;

  CScript spubkey(script_pubkey.begin(), script_pubkey.end());
  if (spubkey.empty())
    return std::nullopt;

  return VerifyScript(ssig, spubkey, nullptr, SCRIPT_VERIFY_NONE,
                      FuzzedSignatureChecker(), nullptr);
}

namespace {
void EnsureECCContextInitialized() {
  static bool ecc_context_initialized = false;
  static ECC_Context ecc_context{};
  if (!ecc_context_initialized) {
    SelectParams(ChainType::MAIN);
    ecc_context_initialized = true;
  }
}

void EnsureTestDataInitialized() {
  static bool test_data_initialized = false;
  if (!test_data_initialized) {
    TEST_DATA.Init();
    test_data_initialized = true;
  }
}
} // namespace

std::optional<bool> Bitcoin::descriptor_parse(std::string str) const {
  EnsureECCContextInitialized();

  FlatSigningProvider signing_provider;
  std::string error;
  const auto desc =
      Parse(str, signing_provider, error, /*require_checksum=*/false);
  return !desc.empty();
}

std::optional<bool> Bitcoin::miniscript_parse(std::string str) const {
  EnsureECCContextInitialized();

  EnsureTestDataInitialized();

  const ParserContext parser_ctx{miniscript::MiniscriptContext::P2WSH};
  auto ret{miniscript::FromString(str, parser_ctx)};
  if (ret && ret->IsSane()) {
    return true;
  }

  const ParserContext parser_ctx_tap{miniscript::MiniscriptContext::TAPSCRIPT};
  ret = miniscript::FromString(str, parser_ctx_tap);
  if (ret && ret->IsSane()) {
    return true;
  }

  return false;
}

std::optional<std::string>
Bitcoin::deserialize_block(std::span<const uint8_t> buffer) const {
  DataStream ds{buffer};
  CBlock block;
  try {
    ds >> TX_WITH_WITNESS(block);
  } catch (const std::ios_base::failure &) {
    return std::nullopt;
  }
  static bool initialized = false;
  if (!initialized) {
    SelectParams(ChainType::MAIN);
    initialized = true;
  }
  BlockValidationState state;
  if (!CheckBlock(block, state, Params().GetConsensus(), /*fCheckPOW=*/false)) {
    return "0";
  }
  if (IsBlockMutated(block, /*check_witness_root=*/true)) {
    return "0";
  }
  return block.GetHash().ToString();
}

std::optional<std::string>
Bitcoin::transaction_eval(std::span<const uint8_t> buffer) const {
  DataStream ds_mtx{buffer};
  CMutableTransaction mutable_tx;
  try {
    ds_mtx >> TX_WITH_WITNESS(mutable_tx);
  } catch (const std::ios_base::failure &e) {
    return "0";
  }

  CTransaction tx{mutable_tx};
  TxValidationState state;
  if (!CheckTransaction(tx, state))
    return "0";

  auto res{tx.GetWitnessHash().ToString()};
  res += std::to_string(tx.ComputeTotalSize());

  return res;
}

std::optional<std::string> Bitcoin::merkle_root_compute(
    const std::vector<std::vector<uint8_t>> &hashes) const {
  std::vector<uint256> leaves;
  leaves.reserve(hashes.size());
  for (const auto &hash : hashes) {
    if (hash.size() != 32)
      return std::nullopt;
    // Input bytes are the hash in internal (serialized) byte order.
    leaves.emplace_back(std::span<const uint8_t>{hash});
  }

  bool mutated{false};
  const uint256 root{ComputeMerkleRoot(std::move(leaves), &mutated)};

  // Root in display byte order, plus the CVE-2012-2459 mutation flag.
  return root.ToString() + ";mutated=" + (mutated ? "1" : "0");
}

std::optional<std::string>
Bitcoin::sighash_compute(const SighashComputeInput &input) const {
  CMutableTransaction mutable_tx;
  DataStream ds{input.tx_bytes};
  try {
    ds >> TX_WITH_WITNESS(mutable_tx);
  } catch (const std::ios_base::failure &e) {
    return std::nullopt;
  }

  if (mutable_tx.vin.empty())
    return std::nullopt;
  CTransaction tx{mutable_tx};
  const unsigned int n_in{input.input_index %
                          static_cast<uint32_t>(tx.vin.size())};

  // Truncate the script right after the n-th OP_CODESEPARATOR, using Core's
  // own script iterator (mirrors pbegincodehash in EvalScript/EvalChecksig).
  const CScript script(input.script.begin(), input.script.end());
  size_t script_begin{0};
  if (input.n_codesep > 0) {
    uint32_t seen{0};
    size_t last_codesep_end{0};
    CScript::const_iterator pc{script.begin()};
    opcodetype opcode;
    while (script.GetOp(pc, opcode)) {
      if (opcode == OP_CODESEPARATOR) {
        last_codesep_end = pc - script.begin();
        if (++seen == input.n_codesep)
          break;
      }
    }
    // If the script contains fewer than n_codesep separators, clamp to the
    // last one found (0 here means none found, i.e. no truncation).
    script_begin = last_codesep_end;
  }
  CScript script_code(script.begin() + script_begin, script.end());

  // Legacy: drop the signature being checked from the script code, exactly
  // like EvalChecksigPreTapscript does. Segwit v0 keeps it as-is (BIP143).
  if (!input.is_segwit_v0 && !input.sig_to_delete.empty()) {
    FindAndDelete(script_code, CScript() << input.sig_to_delete);
  }

  const uint256 sighash{SignatureHash(
      script_code, tx, n_in, static_cast<int32_t>(input.sighash_type),
      CAmount(input.amount),
      input.is_segwit_v0 ? SigVersion::WITNESS_V0 : SigVersion::BASE)};

  return sighash.ToString();
}

std::optional<std::string> Bitcoin::address_parse(std::string str) const {
  static bool initialized = false;
  if (!initialized) {
    SelectParams(ChainType::MAIN);
    initialized = true;
  }
  try {
    CTxDestination dest = DecodeDestination(str);
    if (IsValidDestination(dest)) {
      std::string result;

      if (std::holds_alternative<PKHash>(dest)) {
        result = "PKH:";
      } else if (std::holds_alternative<ScriptHash>(dest)) {
        result = "SH:";
      } else if (std::holds_alternative<WitnessV0KeyHash>(dest)) {
        result = "WPKH:";
      } else if (std::holds_alternative<WitnessV0ScriptHash>(dest)) {
        result = "WSH:";
      } else if (std::holds_alternative<WitnessV1Taproot>(dest)) {
        result = "TR:";
      } else {
        result = "UNK:";
      }

      return result + EncodeDestination(dest);
    }
    return "INVALID";
  } catch (const std::exception &) {
    return "INVALID";
  }
}

std::optional<std::string>
Bitcoin::addrv2_parse(std::span<const uint8_t> buffer) const {
  std::vector<CAddress> addrs;
  DataStream ds{buffer};
  try {
    ds >> CAddress::V2_NETWORK(addrs);
  } catch (const std::ios_base::failure &e) {
    return "[]";
  }

  std::string result = "[";
  bool first = true;
  for (const auto &addr : addrs) {
    if (!addr.IsRoutable()) {
      continue;
    }

    if (!first) {
      result += ",";
    }
    first = false;

    auto addr_bytes = addr.GetAddrBytes();
    std::string addr_hex;
    if (addr.IsIPv4() && addr_bytes.size() == 16) {
      // GetAddrBytes returns IPv4-mapped IPv6 format (16 bytes), extract last 4
      // bytes
      addr_hex = HexStr(std::span(addr_bytes).last(4));
    } else {
      addr_hex = HexStr(addr_bytes);
    }
    uint32_t time =
        static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                  addr.nTime.time_since_epoch())
                                  .count());
    uint64_t services = static_cast<uint64_t>(addr.nServices);
    uint16_t port = addr.GetPort();

    std::string addr_type;
    if (addr.IsIPv4()) {
      addr_type = "ipv4";
    } else if (addr.IsIPv6()) {
      addr_type = "ipv6";
    } else if (addr.IsTor()) {
      addr_type = "tor";
    } else if (addr.IsI2P()) {
      addr_type = "i2p";
    } else if (addr.IsCJDNS()) {
      addr_type = "cjdns";
    }

    result += "{\"addr\":\"" + addr_hex + "\",\"type\":\"" + addr_type +
              "\",\"time\":\"" + std::to_string(time) + "\",\"services\":\"" +
              std::to_string(services) + "\",\"port\":\"" +
              std::to_string(port) + "\"}";
  }
  result += "]";

  return result;
}

namespace {
// Computes the BIP-370 "effective" lock time for a PSBT, mirroring the
// rust-psbt crate's `v2::Psbt::determine_lock_time`. PSBTv0 inputs never
// carry a required time/height locktime, so for PSBTv0 this always reduces
// to the fallback locktime taken from the embedded unsigned tx, keeping the
// output identical to before for PSBTv0 PSBTs.
std::optional<uint32_t>
DeterminePSBTLockTime(const PartiallySignedTransaction &psbt) {
  bool require_time = false;
  bool require_height = false;
  bool have_lock_time = false;
  for (const PSBTInput &input : psbt.inputs) {
    const bool has_time{input.time_locktime.has_value()};
    const bool has_height{input.height_locktime.has_value()};
    if (has_time || has_height) {
      have_lock_time = true;
    }
    if (has_time && !has_height) {
      require_time = true;
    }
    if (has_height && !has_time) {
      require_height = true;
    }
  }
  // BIP-370: an input requiring a time-based lock time and another
  // requiring a height-based one is an unsatisfiable combination.
  if (require_time && require_height) {
    return std::nullopt;
  }
  if (!have_lock_time) {
    return psbt.fallback_locktime.value_or(0);
  }
  std::optional<uint32_t> result;
  for (const PSBTInput &input : psbt.inputs) {
    const std::optional<uint32_t> &candidate{
        require_time ? input.time_locktime : input.height_locktime};
    if (candidate.has_value()) {
      result = result.has_value() ? std::max(*result, *candidate) : *candidate;
    }
  }
  return result;
}
} // namespace

std::optional<std::string>
Bitcoin::psbt_parse(std::span<const uint8_t> buffer) const {
  if (buffer.empty()) {
    return std::nullopt;
  }

  util::Result<PartiallySignedTransaction> psbt_result{
      DecodeRawPSBT(std::as_bytes(buffer))};
  if (!psbt_result) {
    return std::string{"INVALID"};
  }
  const PartiallySignedTransaction psbt{*psbt_result};

  std::string result;

  try {
    // Extract high-level transaction properties (matching rust-bitcoin format)
    // result += "v=" + std::to_string(tx.version) + ";";
    const std::optional<uint32_t> lock_time{DeterminePSBTLockTime(psbt)};
    if (!lock_time.has_value()) {
      // Conflicting per-input lock time requirements (BIP-370). This is a
      // well-defined "reject" outcome, not a generic parse failure, so use a
      // non-empty sentinel (the driver's PSBTParseTarget skips empty results
      // from comparison entirely) to confirm every module agrees on
      // rejecting it, mirroring the other PSBTv2-aware modules.
      return std::string{"CONFLICTING_LOCKTIME"};
    }
    result += "lock_time=" + std::to_string(*lock_time) + ";";
    result += "inputs=" + std::to_string(psbt.inputs.size()) + ";";
    result += "outputs=" + std::to_string(psbt.outputs.size()) + ";";

    // Extract input information (matching rust-bitcoin format exactly)
    for (size_t i = 0; i < psbt.inputs.size(); i++) {
      const PSBTInput &psbt_input{psbt.inputs.at(i)};

      // Previous output reference in format "txid:vout"
      result += "input" + std::to_string(i) +
                "previous_output=" + psbt_input.prev_txid.ToString() + ":" +
                std::to_string(psbt_input.prev_out) + ";";

      // Sequence number
      const auto sequence{psbt_input.sequence.has_value()
                              ? std::to_string(psbt_input.sequence.value())
                              : ""};
      result += "input" + std::to_string(i) + "sequence=" + sequence + ";";

      // UTXO availability (check both witness and non-witness UTXO)
      bool has_utxo = false;
      if (!psbt_input.witness_utxo.IsNull() || psbt_input.non_witness_utxo) {
        has_utxo = true;
      }
      if (has_utxo) {
        result += "input" + std::to_string(i) + "utxo=1;";
      }

      // Partial signatures count
      result += "input" + std::to_string(i) + "partial_signatures=" +
                std::to_string(psbt_input.partial_sigs.size()) + ";";

      // Redeem/witness scripts as hex
      result += "input" + std::to_string(i) +
                "redeem_script=" + HexStr(psbt_input.redeem_script) + ";";
      result += "input" + std::to_string(i) +
                "witness_script=" + HexStr(psbt_input.witness_script) + ";";

      // Sighash type (0 if unset)
      result += "input" + std::to_string(i) + "sighash_type=" +
                std::to_string(static_cast<uint32_t>(
                    psbt_input.sighash_type.value_or(0))) +
                ";";

      // BIP32 derivation count
      result += "input" + std::to_string(i) +
                "bip32=" + std::to_string(psbt_input.hd_keypaths.size()) + ";";

      // Finalized status
      if (!psbt_input.final_script_sig.empty() ||
          !psbt_input.final_script_witness.IsNull()) {
        result += "input" + std::to_string(i) + "finalized=1;";
      }
    }

    // Extract output information
    for (size_t i = 0; i < psbt.outputs.size(); i++) {
      const PSBTOutput &psbt_output{psbt.outputs.at(i)};

      // Output value (cast to int64_t to match rust-bitcoin's i64 cast)
      result += "output" + std::to_string(i) + "val=" +
                std::to_string(static_cast<int64_t>(psbt_output.amount)) + ";";

      // Output script as hex string
      result += "output" + std::to_string(i) +
                "script=" + HexStr(psbt_output.script) + ";";

      // Redeem/witness scripts as hex
      result += "output" + std::to_string(i) +
                "redeem_script=" + HexStr(psbt_output.redeem_script) + ";";
      result += "output" + std::to_string(i) +
                "witness_script=" + HexStr(psbt_output.witness_script) + ";";

      // BIP32 derivation count
      result += "output" + std::to_string(i) +
                "bip32=" + std::to_string(psbt_output.hd_keypaths.size()) + ";";
    }

  } catch (const std::exception &e) {
    return std::string{"INVALID"};
  }

  return result;
}

namespace {
// CBlockHeaderAndShortTxIDs keeps prefilledtxn protected with no public
// accessor; subclass it to read the prefilled transactions while inheriting
// Core's exact deserialization (so the wire format can't drift).
class PublicHeaderAndShortTxIDs : public CBlockHeaderAndShortTxIDs {
public:
  const std::vector<PrefilledTransaction> &prefilled() const {
    return prefilledtxn;
  }
};

// rust-bitcoin folds most of Bitcoin Core's context-free CheckTransaction()
// checks (empty vout, output value range, duplicate inputs, coinbase scriptSig
// length, null prevout) into transaction deserialization, so it rejects at
// decode time prefilled transactions that Core happily deserializes and only
// later rejects in CheckTransaction(). The one exception is empty vin: its
// decoder treats a zero-input vector as the segwit marker and accepts the tx,
// so the rust-bitcoin harness rejects that case manually instead. Running
// CheckTransaction() here covers both: it lets us skip the comparison whenever
// rust-bitcoin would reject (at decode or by hand), keeping the two engines
// symmetric.
bool CompactBlockHasSkippedPrefilledTx(std::span<const uint8_t> buffer) {
  DataStream ds{buffer};
  PublicHeaderAndShortTxIDs compact_block;
  try {
    ds >> compact_block;
  } catch (const std::exception &) {
    return false;
  }

  for (const auto &prefilled_tx : compact_block.prefilled()) {
    TxValidationState state;
    if (!CheckTransaction(*prefilled_tx.tx, state)) {
      return true;
    }
  }
  return false;
}
} // namespace

std::optional<std::string>
Bitcoin::cmpctblocks_parse(std::span<const uint8_t> buffer) const {
  if (CompactBlockHasSkippedPrefilledTx(buffer)) {
    return std::nullopt;
  }

  DataStream ds{buffer};
  CBlockHeaderAndShortTxIDs block_header_and_short_txids;

  try {
    ds >> block_header_and_short_txids;
  } catch (const std::ios_base::failure &e) {
    if (std::string(e.what()).find("Superfluous witness record") !=
        std::string::npos)
      return std::nullopt;
    return "ERR:parse";
  }

  if (!ds.empty()) {
    return "ERR:trailing_bytes";
  }

  DataStream temp_ds{};
  try {
    temp_ds << block_header_and_short_txids;
    return "OK:header=" +
           block_header_and_short_txids.header.GetHash().ToString() +
           ";tx_count=" +
           std::to_string(block_header_and_short_txids.BlockTxCount()) +
           ";ser=" +
           HexStr(std::span<const std::byte>{temp_ds.data(), temp_ds.size()});
  } catch (const std::exception &e) {
    return "ERR:serialize";
  }
}

std::optional<std::string>
Bitcoin::bip32_master_keygen(std::span<const uint8_t> seed) const {
  if (seed.size() < 16 || seed.size() > 64) {
    return std::nullopt; // CExtKey::SetSeed() asserts the BIP32 seed length,
                         // see key.cpp in Bitcoin Core
  }

  SelectParams(ChainType::MAIN);
  CExtKey master;
  master.SetSeed(
      std::span{reinterpret_cast<const std::byte *>(seed.data()), seed.size()});
  return EncodeExtKey(master);
}

std::optional<std::string>
Bitcoin::bip32_deserialize_extended_key(std::span<const uint8_t> buffer) const {
  const std::string ext_str(reinterpret_cast<const char *>(buffer.data()),
                            buffer.size());

  if (ext_str[0] != 'x' && ext_str[0] != 't')
    return "INVALID";
  SelectParams(ext_str[0] == 't'
                   ? ChainType::TESTNET
                   : ChainType::MAIN); // needs to be done this way due to how
                                       // Params() works

  /* xprv / tprv */
  try {
    CExtKey ext_key = DecodeExtKey(ext_str);
    if (ext_key.key.size() ==
        0) { // if DecodeExtKey failed, it returns a CExtKey with empty key
      throw std::runtime_error("DecodeExtKey failed");
    }

    std::string result = strprintf(
        "depth=%02x;fp=%02x%02x%02x%02x;child=%08x;chaincode=%s;key=%s",
        ext_key.nDepth, ext_key.fingerprint[0], ext_key.fingerprint[1],
        ext_key.fingerprint[2], ext_key.fingerprint[3], ext_key.nChild,
        HexStr(ext_key.chaincode), HexStr(ext_key.key));
    return result;
  } catch (...) {
    /* fall through */
  }

  /* xpub / tpub */
  try {
    CExtPubKey ext_pubkey = DecodeExtPubKey(ext_str);
    if ((ext_pubkey.pubkey.size() == 0)) {
      throw std::runtime_error("DecodeExtPubKey failed");
    }

    std::string result = strprintf(
        "depth=%02x;fp=%02x%02x%02x%02x;child=%08x;chaincode=%s;key=%s",
        ext_pubkey.nDepth, ext_pubkey.fingerprint[0], ext_pubkey.fingerprint[1],
        ext_pubkey.fingerprint[2], ext_pubkey.fingerprint[3], ext_pubkey.nChild,
        HexStr(ext_pubkey.chaincode), HexStr(ext_pubkey.pubkey));
    return result;
  } catch (...) {
    return "INVALID";
  }
}

std::optional<std::string>
Bitcoin::bip32_derive_from_path(std::span<const uint8_t> buffer) const {
  std::string path_str(reinterpret_cast<const char *>(buffer.data()),
                       buffer.size());

  // Reject hardened notation ('h')
  if (path_str.find('h') != std::string::npos) {
    return std::nullopt;
  }

  // Parse derivation path
  std::vector<uint32_t> path;
  if (!ParseHDKeypath(path_str, path) || path.empty()) {
    return "INVALID";
  }

  static ECC_Context ecc_context;
  SelectParams(ChainType::MAIN);

  constexpr std::array<uint8_t, 32> seed_raw{
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
      0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

  CExtKey key;
  key.SetSeed(std::as_bytes(std::span(seed_raw)));

  for (uint32_t child : path) {
    CExtKey next;
    if (!key.Derive(next, child)) {
      return "INVALID";
    }
    key = next;
  }

  return EncodeExtKey(key);
}

std::optional<std::string>
Bitcoin::aes256_cbc(std::span<const uint8_t> key, std::span<const uint8_t> iv,
                    bool pad, std::span<const uint8_t> data) const {
  const int size = static_cast<int>(data.size());

  const AES256CBCEncrypt enc(key.data(), iv.data(), pad);
  std::vector<uint8_t> ciphertext(data.size() + AES_BLOCKSIZE);
  const int enc_written = enc.Encrypt(data.data(), size, ciphertext.data());
  const std::string enc_res =
      enc_written == 0 ? "ERR"
                       : HexStr(std::span{ciphertext.data(),
                                          static_cast<size_t>(enc_written)});

  const AES256CBCDecrypt dec(key.data(), iv.data(), pad);
  std::vector<uint8_t> plaintext(data.size());
  const int dec_written = dec.Decrypt(data.data(), size, plaintext.data());
  std::string dec_res;
  if (dec_written > 0) {
    dec_res =
        HexStr(std::span{plaintext.data(), static_cast<size_t>(dec_written)});
  } else if (pad && size == AES_BLOCKSIZE) {
    // Decrypt() returns 0 both for invalid padding and for the legitimate
    // empty plaintext (a single block of full PKCS#7 padding). Disambiguate
    // with a raw decryption of the block.
    const AES256CBCDecrypt raw_dec(key.data(), iv.data(), /*padIn=*/false);
    const int raw_written =
        raw_dec.Decrypt(data.data(), size, plaintext.data());
    const bool full_padding =
        raw_written == AES_BLOCKSIZE &&
        std::all_of(plaintext.begin(), plaintext.begin() + AES_BLOCKSIZE,
                    [](uint8_t byte) { return byte == AES_BLOCKSIZE; });
    dec_res = full_padding ? "" : "ERR";
  } else {
    dec_res = "ERR";
  }

  return "enc=" + enc_res + " dec=" + dec_res;
}

} // namespace module
} // namespace bitcoinfuzz
