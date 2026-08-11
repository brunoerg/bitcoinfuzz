#include "module.h"
#include "musig2_lib/musig2_lib.h"
#include <span>

namespace bitcoinfuzz {
namespace module {

RustMusig2::RustMusig2(void) : BaseModule("RustMusig2") {}

std::optional<std::string>
RustMusig2::musig2_key_agg(std::span<const uint8_t> seckeys) const {
  // Input is num_keys concatenated 32-byte private keys; the Rust side derives
  // the pubkeys and aggregates. Returns null on an invalid scalar (-> nullopt,
  // skipped) or the "AGG_FAIL" sentinel if aggregation itself is rejected.
  size_t num_keys = seckeys.size() / 32;

  char *result = ::musig2_key_agg(seckeys.data(), num_keys);
  if (!result)
    return std::nullopt;

  std::string s(result);
  ::musig2_free_string(result);
  return s;
}

std::optional<std::string>
RustMusig2::musig2_sign_session(const Musig2SignSessionInput &input) const {
  const size_t num_keys = input.seckeys.size() / 32;
  // Pack tweaks as 33-byte records (type byte + 32-byte tweak) for the FFI.
  std::vector<uint8_t> tweaks;
  tweaks.reserve(input.tweaks.size() * 33);
  for (const auto &tw : input.tweaks) {
    tweaks.push_back(tw.is_xonly ? 1 : 0);
    tweaks.insert(tweaks.end(), tw.tweak.begin(), tw.tweak.end());
  }
  // Runs a full signing session on the Rust side. Returns null on an invalid
  // scalar (nullopt, skipped), a sentinel ("AGG_FAIL"/"TWEAK_FAIL"/...) on a
  // rejected step, or "aggnonce:partial_sigs:final_sig" hex, matching the
  // secp256k1 module.
  char *result = ::musig2_sign_session(
      input.seckeys.data(), num_keys, input.msg32.data(),
      input.nonce_seeds.data(),
      input.use_extra_input ? input.extra_input.data() : nullptr,
      tweaks.empty() ? nullptr : tweaks.data(), input.tweaks.size());
  if (!result)
    return std::nullopt;

  std::string s(result);
  ::musig2_free_string(result);
  return s;
}

std::optional<std::string>
RustMusig2::musig2_keyagg_ctx(std::span<const uint8_t> buffer) const {
  char *result = ::musig2_keyagg_ctx(buffer.data(), buffer.size());
  if (!result)
    return std::nullopt;

  std::string s(result);
  ::musig2_free_string(result);
  return s;
}

} // namespace module
} // namespace bitcoinfuzz
