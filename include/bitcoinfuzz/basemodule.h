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

  // Deserializes a MuSig2 key aggregation context from its binary format
  // (rust-musig2's KeyAggContext: header byte, optional 32-byte tweak
  // accumulator, u32 BE pubkey count, 33-byte compressed pubkeys) and checks
  // that parse/serialize is idempotent. Returns one of:
  //   "DECODE_ERR"          — the bytes were rejected
  //   "ROUNDTRIP_FAIL:..."  — parsed, but re-serializing and re-parsing did
  //                           not round-trip (library invariant violation;
  //                           the driver treats this as fatal even with a
  //                           single implementing module)
  //   "<aggpub_hex>;<ser_hex>" — aggregated compressed pubkey and canonical
  //                           serialization, in hex
  virtual std::optional<std::string>
  musig2_keyagg_ctx(std::span<const uint8_t> buffer) const;

  virtual ~BaseModule() noexcept;
};
} // namespace bitcoinfuzz
