#include <bitcoinfuzz/basemodule.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace bitcoinfuzz {
namespace module {
class Bitcoin : public BaseModule {
public:
  Bitcoin(void);
  std::optional<std::string>
  script_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  deserialize_block(std::span<const uint8_t> buffer) const override;
  std::optional<bool> script_eval(const std::vector<uint8_t> &input_data,
                                  unsigned int flags,
                                  size_t version) const override;
  std::optional<bool>
  verify_script(const std::vector<uint8_t> &script_sig,
                const std::vector<uint8_t> &script_pubkey) const override;
  std::optional<bool> descriptor_parse(std::string str) const override;
  std::optional<bool> miniscript_parse(std::string str) const override;
  std::optional<std::string> address_parse(std::string str) const override;
  std::optional<std::string>
  addrv2_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  psbt_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  cmpctblocks_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  transaction_eval(std::span<const uint8_t> buffer) const override;
  std::optional<std::string> merkle_root_compute(
      const std::vector<std::vector<uint8_t>> &hashes) const override;
  std::optional<std::string>
  partial_merkle_tree(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  bip32_master_keygen(std::span<const uint8_t> buffer) const override;
  std::optional<std::string> bip32_deserialize_extended_key(
      std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  bip32_derive_from_path(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  aes256_cbc(std::span<const uint8_t> key, std::span<const uint8_t> iv,
             bool pad, std::span<const uint8_t> data) const override;
  ~Bitcoin() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
