#include <bitcoinfuzz/basemodule.h>
#include <optional>
#include <span>
#include <vector>

namespace bitcoinfuzz {
namespace module {
class LibwallyCore : public BaseModule {
public:
  LibwallyCore(void);
  std::optional<std::string>
  psbt_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  bip32_master_keygen(std::span<const uint8_t> buffer) const override;
  std::optional<std::string> bip32_deserialize_extended_key(
      std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  bech32_segwit_roundtrip(const Bech32SegwitInput &input) const override;
  ~LibwallyCore() noexcept override = default;
};
} // namespace module
} // namespace bitcoinfuzz