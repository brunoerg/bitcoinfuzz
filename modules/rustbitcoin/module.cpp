#include <algorithm>
#include <span>

#include "module.h"
#include "rust_bitcoin_lib/rust_bitcoin_lib.h"

namespace bitcoinfuzz {
namespace module {
Rustbitcoin::Rustbitcoin(void) : BaseModule("Rustbitcoin") {}

std::optional<std::string>
Rustbitcoin::script_parse(std::span<const uint8_t> buffer) const {
  auto script{rust_bitcoin_script(buffer.data(), buffer.size())};
  std::string result(script);
  free_c_string(script);
  return result;
}

std::optional<std::string>
Rustbitcoin::deserialize_block(std::span<const uint8_t> buffer) const {
  auto pointer{rust_bitcoin_des_block(buffer.data(), buffer.size())};
  std::string result(pointer);
  free_c_string(pointer);
  if (result == "skip error") {
    return std::nullopt;
  }
  return result;
}

std::optional<std::string> Rustbitcoin::address_parse(std::string str) const {
  auto result_ptr = rust_bitcoin_address_parse(str.c_str());
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string>
Rustbitcoin::psbt_parse(std::span<const uint8_t> buffer) const {
  auto result_ptr = rust_bitcoin_psbt_parse(buffer.data(), buffer.size());
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string>
Rustbitcoin::addrv2_parse(std::span<const uint8_t> buffer) const {
  auto result_ptr = rust_bitcoin_addrv2(buffer.data(), buffer.size());
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string>
Rustbitcoin::cmpctblocks_parse(std::span<const uint8_t> buffer) const {
  auto result_ptr =
      rust_bitcoin_cmpctblocks_parse(buffer.data(), buffer.size());
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string>
Rustbitcoin::parse_p2p_message(std::span<const uint8_t> buffer) const {
  auto message{rust_bitcoin_parse_p2p_message(buffer.data(), buffer.size())};
  if (message == nullptr)
    return std::nullopt;
  std::string result(message);
  free_c_string(message);
  return result;
}

std::optional<std::string>
Rustbitcoin::bip32_master_keygen(std::span<const uint8_t> buffer) const {
  auto result_ptr =
      rust_bitcoin_bip32_master_keygen(buffer.data(), buffer.size());
  if (result_ptr == nullptr)
    return std::nullopt;
  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string> Rustbitcoin::bip32_deserialize_extended_key(
    std::span<const uint8_t> buffer) const {
  auto result_ptr =
      rust_bitcoin_bip32_deserialize_extended_key(buffer.data(), buffer.size());
  if (result_ptr == nullptr)
    return std::nullopt;
  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}
std::optional<std::string>
Rustbitcoin::bip32_derive_from_path(std::span<const uint8_t> buffer) const {
  auto result_ptr =
      rust_bitcoin_bip32_derive_from_path(buffer.data(), buffer.size());
  if (result_ptr == nullptr)
    return std::nullopt;
  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string>
Rustbitcoin::decode_ellswift(std::span<const uint8_t> buffer) const {
  auto result_ptr = rust_bitcoin_decode_ellswift(buffer.data(), buffer.size());
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string>
Rustbitcoin::roundtrip_ellswift(std::span<const uint8_t> privkey) const {
  auto result_ptr =
      rust_bitcoin_roundtrip_ellswift(privkey.data(), privkey.size());
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string> Rustbitcoin::merkle_root_compute(
    const std::vector<std::vector<uint8_t>> &hashes) const {
  // Flatten the 32-byte hashes into a single buffer for the FFI call.
  std::vector<uint8_t> flat;
  flat.reserve(hashes.size() * 32);
  for (const auto &hash : hashes) {
    if (hash.size() != 32)
      return std::nullopt;
    flat.insert(flat.end(), hash.begin(), hash.end());
  }

  auto result_ptr = rust_bitcoin_merkle_root_compute(flat.data(), flat.size());
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

std::optional<std::string>
Rustbitcoin::bech32_segwit_roundtrip(const Bech32SegwitInput &input) const {
  auto result_ptr = rust_bitcoin_bech32_segwit_roundtrip(
      reinterpret_cast<const uint8_t *>(input.hrp.data()), input.hrp.size(),
      input.witver, input.program.data(), input.program.size());
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free_c_string(result_ptr);
  return result;
}

} // namespace module
} // namespace bitcoinfuzz
