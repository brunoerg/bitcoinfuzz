#include <cstring>
#include <span>

#include "gocoin_wrapper/libgocoin_wrapper.h"
#include "module.h"

namespace bitcoinfuzz {
namespace module {
Gocoin::Gocoin(void) : BaseModule("Gocoin") {}

std::optional<bool>
Gocoin::verify_script(const std::vector<uint8_t> &script_sig,
                      const std::vector<uint8_t> &script_pubkey) const {
  ByteArray script_data{.data = reinterpret_cast<char *>(
                            const_cast<uint8_t *>(script_sig.data())),
                        .length = static_cast<int>(script_sig.size())};

  ByteArray script_data2{.data = reinterpret_cast<char *>(
                             const_cast<uint8_t *>(script_pubkey.data())),
                         .length = static_cast<int>(script_pubkey.size())};

  return GocoinVerifyTxScript(script_data, script_data2) == 1;
}

std::optional<bool> Gocoin::script_eval(const std::vector<uint8_t> &input_data,
                                        unsigned int flags,
                                        size_t version) const {
  ByteArray script_data{.data = reinterpret_cast<char *>(
                            const_cast<uint8_t *>(input_data.data())),
                        .length = static_cast<int>(input_data.size())};

  int result = GocoinEvalScript(script_data, /*flags=*/0, version);

  if (result == 1) {
    return true;
  } else if (result == 2) {
    return false;
  }

  return std::nullopt;
}

std::optional<std::string> Gocoin::merkle_root_compute(
    const std::vector<std::vector<uint8_t>> &hashes) const {
  // Flatten the 32-byte hashes into a single buffer for the FFI call.
  std::vector<uint8_t> flat;
  flat.reserve(hashes.size() * 32);
  for (const auto &hash : hashes) {
    if (hash.size() != 32)
      return std::nullopt;
    flat.insert(flat.end(), hash.begin(), hash.end());
  }

  ByteArray data{.data = reinterpret_cast<char *>(flat.data()),
                 .length = static_cast<int>(flat.size())};

  char *result = GocoinMerkleRootCompute(data);
  if (!result)
    return std::nullopt;

  std::string res(result);
  GocoinFreeString(result);
  return res;
}

std::optional<std::string>
Gocoin::sighash_compute(const SighashComputeInput &input) const {
  auto to_byte_array = [](const std::vector<uint8_t> &v) {
    return ByteArray{
        .data = reinterpret_cast<char *>(const_cast<uint8_t *>(v.data())),
        .length = static_cast<int>(v.size())};
  };

  char *result = GocoinSighashCompute(
      to_byte_array(input.tx_bytes), to_byte_array(input.script),
      to_byte_array(input.sig_to_delete), input.input_index, input.n_codesep,
      input.amount, input.sighash_type, input.is_segwit_v0 ? 1 : 0);
  if (!result)
    return std::nullopt;

  std::string res(result);
  GocoinFreeString(result);
  return res;
}

} // namespace module
} // namespace bitcoinfuzz
