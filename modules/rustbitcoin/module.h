#include <bitcoinfuzz/basemodule.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace bitcoinfuzz {
namespace module {
class Rustbitcoin : public BaseModule {
public:
  Rustbitcoin(void);
  std::optional<std::string>
  script_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  deserialize_block(std::span<const uint8_t> buffer) const override;
  std::optional<std::string> address_parse(std::string str) const override;
  std::optional<std::string>
  psbt_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  addrv2_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  cmpctblocks_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  parse_p2p_message(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  bip32_master_keygen(std::span<const uint8_t> buffer) const override;
  std::optional<std::string> bip32_deserialize_extended_key(
      std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  bip32_derive_from_path(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  decode_ellswift(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  roundtrip_ellswift(std::span<const uint8_t> privkey) const override;
  std::optional<std::string> merkle_root_compute(
      const std::vector<std::vector<uint8_t>> &hashes) const override;
  std::optional<std::string>
  sighash_compute(const SighashComputeInput &input) const override;
  ~Rustbitcoin() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
