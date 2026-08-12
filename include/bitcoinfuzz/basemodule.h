#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace bitcoinfuzz {
struct Musig2Tweak {
  bool is_xonly{false};
  std::array<uint8_t, 32> tweak{};
};

struct Musig2SignSessionInput {
  std::vector<uint8_t> seckeys;
  std::vector<uint8_t> msg32;
  std::vector<uint8_t> nonce_seeds;
  // Optional 32-byte extra input mixed into BIP-327 nonce generation.
  bool use_extra_input{false};
  std::vector<uint8_t> extra_input;
  // Applied in order; BIP-327 allows arbitrary chains of x-only and plain
  // tweaks (e.g. plain BIP32 tweaks followed by an x-only taproot tweak).
  std::vector<Musig2Tweak> tweaks;
};

class BaseModule {
public:
  const std::string name;

  BaseModule(const std::string &name) : name(name) {}

  virtual std::optional<std::string>
  script_parse(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  deserialize_block(std::span<const uint8_t> buffer) const;
  virtual std::optional<bool>
  script_eval(const std::vector<uint8_t> &input_data, unsigned int flags,
              size_t version) const;
  virtual std::optional<bool>
  verify_script(const std::vector<uint8_t> &script_sig,
                const std::vector<uint8_t> &script_pubkey) const;
  virtual std::optional<bool> descriptor_parse(std::string str) const;
  virtual std::optional<bool> miniscript_parse(std::string str) const;
  virtual std::optional<std::string> deserialize_invoice(std::string str) const;
  virtual std::optional<std::string> address_parse(std::string str) const;
  virtual std::optional<std::string>
  psbt_parse(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  addrv2_parse(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string> deserialize_offer(std::string str) const;
  virtual std::optional<std::string>
  cmpctblocks_parse(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  parse_p2p_message(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  parse_p2p_lightning_message(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  transaction_eval(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  bip32_master_keygen(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  kernel_block(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  kernel_transaction(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  kernel_block_check(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  private_to_public_key(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  sign_compact(std::span<const uint8_t> buffer,
               std::span<const uint8_t> hash) const;
  virtual std::optional<std::string>
  sign_der(std::span<const uint8_t> buffer,
           std::span<const uint8_t> hash) const;
  virtual std::optional<bool> sign_verify(std::span<const uint8_t> buffer,
                                          std::span<const uint8_t> hash,
                                          std::span<const uint8_t> sign) const;
  virtual std::optional<std::string>
  ecdh(std::span<const uint8_t> buffer, std::span<const uint8_t> pubkey) const;
  virtual std::optional<std::string>
  decode_onion(std::span<const uint8_t> buffer) const;

  virtual std::optional<std::string>
  sign_schnorr(std::span<const uint8_t> buffer, std::span<const uint8_t> hash,
               std::span<const uint8_t> aux) const;
  virtual std::optional<std::string>
  decode_ellswift(std::span<const uint8_t> buffer) const;

  virtual std::optional<std::string>
  roundtrip_ellswift(std::span<const uint8_t> privkey) const;

  virtual std::optional<std::string>
  bip32_deserialize_extended_key(std::span<const uint8_t> buffer) const;

  virtual std::optional<std::string>
  schnorr_verify(std::span<const uint8_t> privkey,
                 std::span<const uint8_t> hash,
                 std::span<const uint8_t> sign) const;

  virtual std::optional<std::string>
  stump_modify_add(const std::vector<std::vector<uint8_t>> &add_hashes) const;

  virtual std::optional<std::string>
  bip32_derive_from_path(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  musig2_key_agg(std::span<const uint8_t> seckeys) const;
  virtual std::optional<std::string>
  aes256_cbc(std::span<const uint8_t> key, std::span<const uint8_t> iv,
             bool pad, std::span<const uint8_t> data) const;
  virtual std::optional<std::string>
  musig2_sign_session(const Musig2SignSessionInput &input) const;
  virtual std::optional<std::string>
  multiindex_ops(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  ordered_unique_ops(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  ordered_non_unique_ops(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  hashed_unique_ops(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  hashed_non_unique_ops(std::span<const uint8_t> buffer) const;

  virtual ~BaseModule() noexcept;
};
} // namespace bitcoinfuzz
