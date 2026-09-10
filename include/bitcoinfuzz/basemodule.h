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

// Sender-side input for BIP-352 Silent Payments output creation.
//
// Both the inputs being spent and the recipient addresses are described by
// secret keys rather than serialized public keys: every module derives the
// public keys itself, which keeps ~100% of fuzzer inputs valid so the budget
// is spent inside the protocol logic instead of on pubkey parsing.
struct SilentPaymentsCreateOutputsInput {
  // Serialized smallest outpoint (lexicographically) of the transaction
  // inputs, as required by BIP-352.
  std::array<uint8_t, 36> outpoint_smallest{};
  // Concatenated 32-byte secret keys of the Silent Payments eligible inputs.
  std::vector<uint8_t> input_seckeys;
  // One flag per input key. Taproot keys are negated to their even-Y form
  // before being summed; non-taproot keys are summed as-is. Not
  // std::vector<bool>: the bytes are handed to a C FFI, so they must be
  // contiguous and addressable.
  std::vector<uint8_t> input_is_taproot;
  // Concatenated 32-byte scan and spend secret keys, one pair per recipient.
  // Recipient i is (scan_seckeys[i*32..], spend_seckeys[i*32..]). Scan keys
  // repeat across recipients so the BIP-352 grouping and k-increment logic is
  // reachable.
  std::vector<uint8_t> scan_seckeys;
  std::vector<uint8_t> spend_seckeys;
  // One flag per recipient, non-zero when that recipient's address is labeled.
  // A labeled address replaces its spend public key with B_spend + m*G, where
  // m = hash_BIP0352/Label(scan_seckey || ser32(label)), so each module has to
  // derive the tweak with its own label API before sending. Modules without one
  // return nullopt for these inputs.
  std::vector<uint8_t> recipient_is_labeled;
  // One label integer per recipient, meaningful only where the flag is set.
  // Drawn from a small pool so the same label repeats across recipients.
  std::vector<uint32_t> recipient_labels;
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
  // Parses a serialized secp256k1 public key (SEC1: 33-byte compressed
  // 0x02/0x03, 65-byte uncompressed 0x04, ...). Returns "ERR" on rejection,
  // or "OK:<33-byte canonical compressed encoding, hex>" on acceptance, so
  // that accept-vs-reject and accepted-point divergences both surface.
  virtual std::optional<std::string>
  pubkey_parse(std::span<const uint8_t> buffer) const;
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

  // Computes the merkle root over a list of raw 32-byte hashes (given in
  // internal byte order, as serialized in a block). The response is either
  // "<root_hex>;mutated=0|1" (root in display byte order, plus whether a
  // CVE-2012-2459-style duplicated subtree was detected) or the sentinel
  // "REJECTED" when the library refuses to compute a root for the list at
  // all (e.g. rust-bitcoin returns None for mutated lists).
  virtual std::optional<std::string>
  merkle_root_compute(const std::vector<std::vector<uint8_t>> &hashes) const;
  // Parses a BIP37 partial Merkle tree (nTransactions u32 LE | CompactSize n
  // | n*32-byte hashes | CompactSize m | m flag bytes) and extracts the
  // matched transactions, emulating CMerkleBlock extraction semantics.
  // Returns one of:
  //   "PARSE_ERR"  — the byte stream is malformed (truncated, non-canonical
  //                  CompactSize, ...)
  //   "REJECT"     — parsed but the tree is invalid (Core's ExtractMatches
  //                  returning the zero hash; covers nTransactions==0,
  //                  too many transactions/hashes, bit/hash underflow during
  //                  traversal, CVE-2012-2459 duplicated branches, trailing
  //                  unconsumed bits or hashes)
  //   "<root_hex>;m=<txid>@<idx>,..." — root and matched txids with their
  //                  leaf indices, in traversal order (display byte order)
  virtual std::optional<std::string>
  partial_merkle_tree(std::span<const uint8_t> buffer) const;

  virtual std::optional<std::string>
  bip32_derive_from_path(std::span<const uint8_t> buffer) const;
  virtual std::optional<std::string>
  musig2_key_agg(std::span<const uint8_t> seckeys) const;
  virtual std::optional<std::string>
  aes256_cbc(std::span<const uint8_t> key, std::span<const uint8_t> iv,
             bool pad, std::span<const uint8_t> data) const;
  virtual std::optional<std::string>
  musig2_sign_session(const Musig2SignSessionInput &input) const;
  virtual std::optional<std::string> silentpayments_create_outputs(
      const SilentPaymentsCreateOutputsInput &input) const;

  virtual ~BaseModule() noexcept;
};
} // namespace bitcoinfuzz
