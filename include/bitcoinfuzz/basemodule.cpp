#include "basemodule.h"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace bitcoinfuzz {
BaseModule::~BaseModule() noexcept {} // Ensures vtable for `Module` is created

std::optional<std::string>
BaseModule::script_parse(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::deserialize_block(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<bool>
BaseModule::script_eval(const std::vector<uint8_t> & /*input_data*/,
                        unsigned int /*flags*/, size_t /*version*/) const {
  return std::nullopt;
}

std::optional<bool> BaseModule::verify_script(
    const std::vector<uint8_t> & /*script_sig*/,
    const std::vector<uint8_t> & /*script_pubkey*/) const {
  return std::nullopt;
}

std::optional<bool> BaseModule::descriptor_parse(std::string /*str*/) const {
  return std::nullopt;
}

std::optional<bool> BaseModule::miniscript_parse(std::string /*str*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::kernel_block(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::kernel_transaction(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::kernel_block_check(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::deserialize_invoice(std::string /*str*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::address_parse(std::string /*str*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::psbt_parse(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::addrv2_parse(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::deserialize_offer(std::string /*str*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::cmpctblocks_parse(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::parse_p2p_message(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::transaction_eval(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string> BaseModule::parse_p2p_lightning_message(
    std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::bip32_master_keygen(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::private_to_public_key(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::pubkey_parse(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::sign_compact(std::span<const uint8_t> /*buffer*/,
                         std::span<const uint8_t> /*hash*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::sign_der(std::span<const uint8_t> /*buffer*/,
                     std::span<const uint8_t> /*hash*/) const {
  return std::nullopt;
}

std::optional<bool>
BaseModule::sign_verify(std::span<const uint8_t> /*buffer*/,
                        std::span<const uint8_t> /*hash*/,
                        std::span<const uint8_t> /*sign*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::ecdh(std::span<const uint8_t> /*buffer*/,
                 std::span<const uint8_t> /*pubkey*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::sign_schnorr(std::span<const uint8_t> /*buffer*/,
                         std::span<const uint8_t> /*hash*/,
                         std::span<const uint8_t> /*aux*/) const {
  return std::nullopt;
}

std::optional<std::string> BaseModule::bip32_deserialize_extended_key(
    std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::decode_ellswift(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::roundtrip_ellswift(std::span<const uint8_t> /*privkey*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::schnorr_verify(std::span<const uint8_t> /*privkey*/,
                           std::span<const uint8_t> /*hash*/,
                           std::span<const uint8_t> /*sign*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::decode_onion(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string> BaseModule::stump_modify_add(
    const std::vector<std::vector<uint8_t>> & /* add_hashes */) const {
  return std::nullopt;
}

std::optional<std::string> BaseModule::merkle_root_compute(
    const std::vector<std::vector<uint8_t>> & /* hashes */) const {
  return std::nullopt;
}

std::optional<std::string> BaseModule::stump_update(
    const std::vector<std::vector<uint8_t>> & /* add_hashes */,
    const std::vector<std::vector<uint8_t>> & /* del_hashes */,
    const std::vector<std::vector<uint8_t>> & /* new_add_hashes */) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::bip32_derive_from_path(std::span<const uint8_t> /*buffer*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::musig2_key_agg(std::span<const uint8_t> /*seckeys*/) const {
  return std::nullopt;
}

std::optional<std::string>
BaseModule::aes256_cbc(std::span<const uint8_t> /*key*/,
                       std::span<const uint8_t> /*iv*/, bool /*pad*/,
                       std::span<const uint8_t> /*data*/) const {
  return std::nullopt;
}
std::optional<std::string> BaseModule::musig2_sign_session(
    const Musig2SignSessionInput & /*input*/) const {
  return std::nullopt;
}

std::optional<std::string> BaseModule::silentpayments_create_outputs(
    const SilentPaymentsCreateOutputsInput & /*input*/) const {
  return std::nullopt;
}

} // namespace bitcoinfuzz
