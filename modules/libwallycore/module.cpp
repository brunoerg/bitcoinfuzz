#define template c_template // avoid C++ keyword conflict just during includes
// Elements support must be disabled and the user must define
// `WALLY_ABI_NO_ELEMENTS` before including all wally header files.
#define WALLY_ABI_NO_ELEMENTS
extern "C" {
#include <ccan/str/hex/hex.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_psbt.h>
}

#undef WALLY_ABI_NO_ELEMENTS
#undef template

#include "module.h"
#include <algorithm>
#include <assert.h>
#include <iomanip>
#include <sstream>

namespace {
// Minimal, self-contained CompactSize (Bitcoin's little-endian varint)
// decoder operating directly on the raw PSBT bytes. Used only to
// disambiguate PSBT_IN_SEQUENCE presence (see V2InputHasExplicitSequence
// below); everything else about the parse is handled by libwally itself.
struct CompactSizeResult {
  bool valid = false;
  uint64_t value = 0;
  size_t bytes_read = 0;
};

CompactSizeResult DecodeCompactSize(const uint8_t *data, size_t available) {
  CompactSizeResult r;
  if (available < 1) {
    return r;
  }
  const uint8_t first = data[0];
  if (first < 253) {
    r.valid = true;
    r.value = first;
    r.bytes_read = 1;
  } else if (first == 253) {
    if (available < 3) {
      return r;
    }
    const uint16_t v =
        static_cast<uint16_t>(data[1]) | (static_cast<uint16_t>(data[2]) << 8);
    if (v < 253) {
      return r; // non-canonical
    }
    r.valid = true;
    r.value = v;
    r.bytes_read = 3;
  } else if (first == 254) {
    if (available < 5) {
      return r;
    }
    const uint32_t v = static_cast<uint32_t>(data[1]) |
                       (static_cast<uint32_t>(data[2]) << 8) |
                       (static_cast<uint32_t>(data[3]) << 16) |
                       (static_cast<uint32_t>(data[4]) << 24);
    if (v < 0x10000u) {
      return r; // non-canonical
    }
    r.valid = true;
    r.value = v;
    r.bytes_read = 5;
  } else {
    if (available < 9) {
      return r;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
      v |= static_cast<uint64_t>(data[1 + i]) << (8 * i);
    }
    if (v < 0x100000000ULL) {
      return r; // non-canonical
    }
    r.valid = true;
    r.value = v;
    r.bytes_read = 9;
  }
  return r;
}

// Advances `offset` past one PSBT key-value map (a run of records
// terminated by a zero-length key). Returns false if the buffer is
// malformed/truncated before reaching the terminator.
bool SkipPsbtMap(std::span<const uint8_t> buf, size_t &offset) {
  while (true) {
    if (offset > buf.size()) {
      return false;
    }
    const CompactSizeResult keylen =
        DecodeCompactSize(buf.data() + offset, buf.size() - offset);
    if (!keylen.valid) {
      return false;
    }
    offset += keylen.bytes_read;
    if (keylen.value == 0) {
      return true; // separator
    }
    if (keylen.value > buf.size() - offset) {
      return false;
    }
    offset += keylen.value;

    const CompactSizeResult vallen =
        DecodeCompactSize(buf.data() + offset, buf.size() - offset);
    if (!vallen.valid) {
      return false;
    }
    offset += vallen.bytes_read;
    if (vallen.value > buf.size() - offset) {
      return false;
    }
    offset += vallen.value;
  }
}

// Scans the map starting at `offset` (advancing it past the map) for a
// record whose key is the single byte `key_type` with no key data. If found
// and `out_value` is non-null, its raw value bytes are copied there.
bool PsbtMapHasSingleByteKey(std::span<const uint8_t> buf, size_t &offset,
                             uint8_t key_type,
                             std::vector<uint8_t> *out_value = nullptr) {
  bool found = false;
  while (true) {
    if (offset > buf.size()) {
      return false;
    }
    const CompactSizeResult keylen =
        DecodeCompactSize(buf.data() + offset, buf.size() - offset);
    if (!keylen.valid) {
      return false;
    }
    offset += keylen.bytes_read;
    if (keylen.value == 0) {
      return found; // separator
    }
    if (keylen.value > buf.size() - offset) {
      return false;
    }
    const bool is_target = (keylen.value == 1 && buf[offset] == key_type);
    offset += keylen.value;

    const CompactSizeResult vallen =
        DecodeCompactSize(buf.data() + offset, buf.size() - offset);
    if (!vallen.valid) {
      return false;
    }
    offset += vallen.bytes_read;
    if (vallen.value > buf.size() - offset) {
      return false;
    }
    if (is_target) {
      found = true;
      if (out_value) {
        out_value->assign(buf.begin() + offset,
                          buf.begin() + offset + vallen.value);
      }
    }
    offset += vallen.value;
  }
}

// Advances `offset` past the global map and the first `target_input_index`
// input maps, positioning it at the start of the target input's map.
bool SeekToInputMap(std::span<const uint8_t> buffer, size_t target_input_index,
                    size_t &offset) {
  static constexpr uint8_t kMagic[5] = {'p', 's', 'b', 't', 0xff};
  if (buffer.size() < sizeof(kMagic) ||
      !std::equal(kMagic, kMagic + sizeof(kMagic), buffer.begin())) {
    return false;
  }
  offset = sizeof(kMagic);
  if (!SkipPsbtMap(buffer, offset)) {
    return false; // global map
  }
  for (size_t i = 0; i < target_input_index; i++) {
    if (!SkipPsbtMap(buffer, offset)) {
      return false;
    }
  }
  return true;
}

// libwally represents an input's sequence number as a plain uint32_t,
// defaulting to WALLY_TX_SEQUENCE_FINAL (0xffffffff) both when
// PSBT_IN_SEQUENCE is explicitly set to that value and when it's omitted
// entirely (BIP-370: omitted sequence is interpreted as final), so the
// struct alone can't distinguish the two. Bitcoin Core/rust-psbt's PSBT
// structs use an optional field and format an *omitted* sequence as an
// empty string, so match that here only for the ambiguous case by
// re-scanning the raw input map for an explicit PSBT_IN_SEQUENCE record.
constexpr uint8_t PSBT_IN_SEQUENCE_KEY = 0x10;
constexpr uint8_t PSBT_IN_OUTPUT_INDEX_KEY = 0x0f;

bool V2InputHasExplicitSequence(std::span<const uint8_t> buffer,
                                size_t target_input_index) {
  size_t offset;
  if (!SeekToInputMap(buffer, target_input_index, offset)) {
    return false;
  }
  return PsbtMapHasSingleByteKey(buffer, offset, PSBT_IN_SEQUENCE_KEY);
}

// libwally's wally_psbt_input::index has its top 2 bits masked off
// unconditionally (WALLY_TX_INDEX_MASK = 0x3fffffff, in
// wally_psbt_input_set_output_index/psbt.c), a behavior inherited from
// Elements' repurposing of those bits as pegin/issuance flags that applies
// even though this build has Elements support disabled. BIP-370 doesn't
// restrict PSBT_IN_OUTPUT_INDEX's range and Bitcoin Core reads it literally,
// so silently trusting libwally's masked field would format a different
// (truncated) index whenever the top bits are set. Read the true on-the-wire
// value ourselves instead.
std::optional<uint32_t> V2InputRawOutputIndex(std::span<const uint8_t> buffer,
                                              size_t target_input_index) {
  size_t offset;
  if (!SeekToInputMap(buffer, target_input_index, offset)) {
    return std::nullopt;
  }
  std::vector<uint8_t> value;
  if (!PsbtMapHasSingleByteKey(buffer, offset, PSBT_IN_OUTPUT_INDEX_KEY,
                               &value) ||
      value.size() != 4) {
    return std::nullopt;
  }
  return static_cast<uint32_t>(value[0]) |
         (static_cast<uint32_t>(value[1]) << 8) |
         (static_cast<uint32_t>(value[2]) << 16) |
         (static_cast<uint32_t>(value[3]) << 24);
}

// Computes the BIP-370 "effective" lock time for a PSBTv2, mirroring the
// same algorithm used by the Bitcoin Core and rust-psbt modules
// (v2::Psbt::determine_lock_time). Returns std::nullopt if inputs disagree
// on whether a time- or height-based lock time is required.
std::optional<uint32_t> DetermineV2LockTime(const struct wally_psbt *psbt) {
  bool require_time = false;
  bool require_height = false;
  bool have_lock_time = false;
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    const wally_psbt_input &input = psbt->inputs[i];
    const bool has_time = input.required_locktime != 0;
    const bool has_height = input.required_lockheight != 0;
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
  if (require_time && require_height) {
    return std::nullopt;
  }
  if (!have_lock_time) {
    return psbt->has_fallback_locktime ? psbt->fallback_locktime : 0;
  }
  std::optional<uint32_t> result;
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    const wally_psbt_input &input = psbt->inputs[i];
    const uint32_t candidate =
        require_time ? input.required_locktime : input.required_lockheight;
    if (candidate != 0) {
      result = result.has_value() ? std::max(*result, candidate) : candidate;
    }
  }
  return result;
}

// BIP-174 keytypes for redeem/witness scripts. Unlike Bitcoin Core/rust-psbt,
// libwally doesn't expose these as dedicated struct fields on
// wally_psbt_input/wally_psbt_output; they live in the generic per-field map
// (`psbt_fields`), keyed by these values (see
// external/libwally-core/src/psbt_io.h).
constexpr uint32_t PSBT_IN_REDEEM_SCRIPT_KT = 0x04;
constexpr uint32_t PSBT_IN_WITNESS_SCRIPT_KT = 0x05;
constexpr uint32_t PSBT_IN_FINAL_SCRIPTSIG_KT = 0x07;
constexpr uint32_t PSBT_OUT_REDEEM_SCRIPT_KT = 0x00;
constexpr uint32_t PSBT_OUT_WITNESS_SCRIPT_KT = 0x01;

// Returns the hex-encoded value stored under `keytype` in `fields`, or an
// empty string if absent.
std::string GetMapFieldHex(const wally_map &fields, uint32_t keytype) {
  const wally_map_item *item = wally_map_get_integer(&fields, keytype);
  if (!item || item->value_len == 0) {
    return std::string{};
  }
  std::vector<char> hex(item->value_len * 2 + 1);
  bool ok = hex_encode(item->value, item->value_len, hex.data(), hex.size());
  assert(ok);
  return std::string(hex.data());
}

// Whether the input carries a *non-empty* final scriptSig or scriptWitness.
// Deliberately not wally_psbt_input_is_finalized(), which keys off the mere
// presence of `final_witness`: Bitcoin Core stores its final witness as a plain
// CScriptWitness whose IsNull() is just stack.empty(), so Core cannot
// distinguish an absent PSBT_IN_FINAL_SCRIPTWITNESS key from one present with a
// zero-item stack. Comparing on emptiness keeps the `fin` flag comparable
// across modules for that degenerate input -- and an empty witness finalizes
// nothing anyway.
bool IsFinalized(const wally_psbt_input &input) {
  if (input.final_witness != nullptr && input.final_witness->num_items > 0) {
    return true;
  }
  return !GetMapFieldHex(input.psbt_fields, PSBT_IN_FINAL_SCRIPTSIG_KT).empty();
}
} // namespace

namespace bitcoinfuzz {
namespace module {
LibwallyCore::LibwallyCore(void) : BaseModule("LibwallyCore") {}

std::optional<std::string>
LibwallyCore::psbt_parse(std::span<const uint8_t> buffer) const {
  struct wally_psbt *psbt;
  int res = wally_psbt_from_bytes(buffer.data(), buffer.size(),
                                  WALLY_PSBT_PARSE_FLAG_STRICT, &psbt);
  if (res != WALLY_OK) {
    return std::string{"INVALID"};
  }

  std::ostringstream result;

  if (psbt->tx) {
    // PSBTv0: the global unsigned tx carries locktime/inputs/outputs.
    result << "lock_time=" << psbt->tx->locktime << ";";
    result << "inputs=" << psbt->tx->num_inputs << ";";
    result << "outputs=" << psbt->tx->num_outputs << ";";

    for (size_t i = 0; i < psbt->tx->num_inputs; i++) {
      if (i < psbt->num_inputs) {
        wally_tx_input txin = psbt->tx->inputs[i];
        wally_psbt_input psbt_input = psbt->inputs[i];
        std::array<uint8_t, 32> txhash_reversed;
        std::reverse_copy(txin.txhash, txin.txhash + 32,
                          txhash_reversed.begin());

        std::vector<char> txhash_hex(65);
        bool ok = hex_encode(txhash_reversed.data(), 32, txhash_hex.data(),
                             txhash_hex.size());
        assert(ok);
        result << "input" << i << "previous_output=" << txhash_hex.data() << ":"
               << txin.index << ";";
        result << "input" << i << "sequence=" << txin.sequence << ";";

        if (psbt_input.utxo || psbt_input.witness_utxo) {
          result << "input" << i << "utxo=1" << ";";
        }

        result << "input" << i
               << "partial_signatures=" << psbt_input.signatures.num_items
               << ";";

        result << "input" << i << "redeem_script="
               << GetMapFieldHex(psbt_input.psbt_fields,
                                 PSBT_IN_REDEEM_SCRIPT_KT)
               << ";";
        result << "input" << i << "witness_script="
               << GetMapFieldHex(psbt_input.psbt_fields,
                                 PSBT_IN_WITNESS_SCRIPT_KT)
               << ";";
        result << "input" << i << "sighash_type=" << psbt_input.sighash << ";";
        result << "input" << i << "bip32=" << psbt_input.keypaths.num_items
               << ";";

        if (IsFinalized(psbt_input)) {
          result << "input" << i << "finalized=1;";
        }
      }
    }

    for (size_t i = 0; i < psbt->tx->num_outputs; i++) {
      wally_tx_output txout = psbt->tx->outputs[i];
      size_t hex_len = txout.script_len * 2 + 1;
      std::vector<char> script_hex(hex_len);

      bool ok = hex_encode(txout.script, txout.script_len, script_hex.data(),
                           script_hex.size());

      assert(ok);
      // Cast to int64_t to match the Bitcoin Core/rust-bitcoin modules'
      // convention (see modules/bitcoin/module.cpp), so a fuzzer-generated
      // amount near UINT64_MAX formats identically instead of one module
      // printing it as a huge unsigned value and the others as negative.
      result << "output" << i << "val=" << static_cast<int64_t>(txout.satoshi)
             << ";";
      result << "output" << i << "script=" << script_hex.data() << ";";

      if (i < psbt->num_outputs) {
        const wally_psbt_output &psbt_output = psbt->outputs[i];
        result << "output" << i << "redeem_script="
               << GetMapFieldHex(psbt_output.psbt_fields,
                                 PSBT_OUT_REDEEM_SCRIPT_KT)
               << ";";
        result << "output" << i << "witness_script="
               << GetMapFieldHex(psbt_output.psbt_fields,
                                 PSBT_OUT_WITNESS_SCRIPT_KT)
               << ";";
        result << "output" << i << "bip32=" << psbt_output.keypaths.num_items
               << ";";
      }
    }
  } else {
    // PSBTv2 (BIP-370): tx data is per-input/output instead of a global
    // unsigned tx.
    const std::optional<uint32_t> lock_time = DetermineV2LockTime(psbt);
    if (!lock_time.has_value()) {
      wally_psbt_free(psbt);
      // Conflicting per-input lock time requirements (BIP-370). This is a
      // well-defined "reject" outcome, not a generic parse failure, so use a
      // non-empty sentinel (the driver's PSBTParseTarget skips empty results
      // from comparison entirely) to confirm every module agrees on
      // rejecting it, mirroring the other PSBTv2-aware modules.
      return std::string{"CONFLICTING_LOCKTIME"};
    }

    result << "lock_time=" << *lock_time << ";";
    result << "inputs=" << psbt->num_inputs << ";";
    result << "outputs=" << psbt->num_outputs << ";";

    for (size_t i = 0; i < psbt->num_inputs; i++) {
      const wally_psbt_input &psbt_input = psbt->inputs[i];
      std::array<uint8_t, 32> txhash_reversed;
      std::reverse_copy(psbt_input.txhash, psbt_input.txhash + 32,
                        txhash_reversed.begin());

      std::vector<char> txhash_hex(65);
      bool ok = hex_encode(txhash_reversed.data(), 32, txhash_hex.data(),
                           txhash_hex.size());
      assert(ok);
      result << "input" << i << "previous_output=" << txhash_hex.data() << ":"
             << V2InputRawOutputIndex(buffer, i).value_or(psbt_input.index)
             << ";";

      if (psbt_input.sequence != WALLY_TX_SEQUENCE_FINAL ||
          V2InputHasExplicitSequence(buffer, i)) {
        result << "input" << i << "sequence=" << psbt_input.sequence << ";";
      } else {
        result << "input" << i << "sequence=" << ";";
      }

      if (psbt_input.utxo || psbt_input.witness_utxo) {
        result << "input" << i << "utxo=1" << ";";
      }

      result << "input" << i
             << "partial_signatures=" << psbt_input.signatures.num_items << ";";

      result << "input" << i << "redeem_script="
             << GetMapFieldHex(psbt_input.psbt_fields, PSBT_IN_REDEEM_SCRIPT_KT)
             << ";";
      result << "input" << i << "witness_script="
             << GetMapFieldHex(psbt_input.psbt_fields,
                               PSBT_IN_WITNESS_SCRIPT_KT)
             << ";";
      result << "input" << i << "sighash_type=" << psbt_input.sighash << ";";
      result << "input" << i << "bip32=" << psbt_input.keypaths.num_items
             << ";";

      if (IsFinalized(psbt_input)) {
        result << "input" << i << "finalized=1;";
      }
    }

    for (size_t i = 0; i < psbt->num_outputs; i++) {
      const wally_psbt_output &psbt_output = psbt->outputs[i];
      size_t hex_len = psbt_output.script_len * 2 + 1;
      std::vector<char> script_hex(hex_len);

      bool ok = hex_encode(psbt_output.script, psbt_output.script_len,
                           script_hex.data(), script_hex.size());
      assert(ok);
      result << "output" << i << "val="
             << static_cast<int64_t>(psbt_output.has_amount ? psbt_output.amount
                                                            : 0)
             << ";";
      result << "output" << i << "script=" << script_hex.data() << ";";

      result << "output" << i << "redeem_script="
             << GetMapFieldHex(psbt_output.psbt_fields,
                               PSBT_OUT_REDEEM_SCRIPT_KT)
             << ";";
      result << "output" << i << "witness_script="
             << GetMapFieldHex(psbt_output.psbt_fields,
                               PSBT_OUT_WITNESS_SCRIPT_KT)
             << ";";
      result << "output" << i << "bip32=" << psbt_output.keypaths.num_items
             << ";";
    }
  }

  wally_psbt_free(psbt);

  return result.str();
}
std::optional<std::string>
LibwallyCore::bip32_master_keygen(std::span<const uint8_t> seed) const {
  struct ext_key *master_key = nullptr;
  if (seed.size() != BIP32_ENTROPY_LEN_128 &&
      seed.size() != BIP32_ENTROPY_LEN_256 &&
      seed.size() != BIP32_ENTROPY_LEN_512) {
    return std::nullopt; // libwally accepts only 128, 256 or 512 bit seeds, see
                         // is_valid_seed_len(size_t len) in bip32.c
  }
  if (bip32_key_from_seed_alloc(seed.data(), seed.size(),
                                BIP32_VER_MAIN_PRIVATE, 0,
                                &master_key) != WALLY_OK) {
    return "INVALID";
  }

  char *base58 = nullptr;

  int res = bip32_key_to_base58(master_key,
                                0, // 0 = private key
                                &base58);

  wally_free(master_key);

  if (res != WALLY_OK || !base58)
    return "INVALID";

  std::string result(base58);
  wally_free(base58);

  return result;
}

std::optional<std::string> LibwallyCore::bip32_deserialize_extended_key(
    std::span<const uint8_t> buffer) const {

  struct ext_key key;

  int res = bip32_key_from_base58_n(
      reinterpret_cast<const char *>(buffer.data()), buffer.size(), &key);

  if (res != WALLY_OK) {
    return "INVALID";
  }

  std::ostringstream result;

  result << std::hex << std::setfill('0');

  result << "depth=" << std::setw(2) << (int)key.depth << ";";
  result << "fp=";
  for (int i = 0; i < 4; ++i)
    result << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(key.parent160[i]);
  result << ";";
  result << "child=" << std::setw(8) << key.child_num << ";";

  result << "chaincode=";
  for (size_t i = 0; i < sizeof(key.chain_code); ++i)
    result << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(key.chain_code[i]);
  result << ";";

  bool is_private = key.version == BIP32_VER_MAIN_PRIVATE ||
                    key.version == BIP32_VER_TEST_PRIVATE;

  result << "key=";
  if (is_private) {
    for (size_t i = 1; i < sizeof(key.priv_key); ++i) // skip prefix byte
      result << std::setw(2) << std::setfill('0')
             << static_cast<int>(key.priv_key[i]);
  } else {
    for (size_t i = 0; i < sizeof(key.pub_key); ++i)
      result << std::setw(2) << std::setfill('0')
             << static_cast<int>(key.pub_key[i]);
  }
  return result.str();
}

std::optional<std::string>
LibwallyCore::bech32_segwit_roundtrip(const Bech32SegwitInput &input) const {
  // libwally takes and returns the scriptPubKey rather than a bare witness
  // version and program: OP_0 / OP_1..OP_16, a direct push opcode, then the
  // program. Programs here are at most 40 bytes, so the push is always a
  // single-byte length.
  std::vector<unsigned char> script_pubkey;
  script_pubkey.reserve(input.program.size() + 2);
  script_pubkey.push_back(
      input.witver == 0 ? 0x00
                        : static_cast<unsigned char>(0x50 + input.witver));
  script_pubkey.push_back(static_cast<unsigned char>(input.program.size()));
  script_pubkey.insert(script_pubkey.end(), input.program.begin(),
                       input.program.end());

  char *encoded = nullptr;
  if (wally_addr_segwit_from_bytes(script_pubkey.data(), script_pubkey.size(),
                                   input.hrp.c_str(), 0,
                                   &encoded) != WALLY_OK ||
      encoded == nullptr)
    return "ENC:FAIL";

  const std::string address{encoded};
  wally_free_string(encoded);

  unsigned char decoded[WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN];
  size_t written = 0;
  if (wally_addr_segwit_to_bytes(address.c_str(), input.hrp.c_str(), 0, decoded,
                                 sizeof(decoded), &written) != WALLY_OK ||
      written < 2)
    return "ENC:" + address + "|DEC:FAIL";

  const unsigned char version_opcode = decoded[0];
  const unsigned int version =
      version_opcode == 0x00 ? 0u : version_opcode - 0x50u;

  std::ostringstream program;
  program << std::hex << std::setfill('0');
  for (size_t i = 2; i < written; ++i)
    program << std::setw(2) << static_cast<unsigned int>(decoded[i]);

  return "ENC:" + address + "|DEC:v" + std::to_string(version) + ":" +
         program.str();
}

} // namespace module
} // namespace bitcoinfuzz
