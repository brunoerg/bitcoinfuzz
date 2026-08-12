#include <bitcoinfuzz/basemodule.h>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace bitcoinfuzz {
namespace module {
class Tmi2 : public BaseModule {
public:
  Tmi2(void);
  std::optional<std::string>
  multiindex_ops(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  ordered_unique_ops(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  ordered_non_unique_ops(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  hashed_unique_ops(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  hashed_non_unique_ops(std::span<const uint8_t> buffer) const override;
  ~Tmi2() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
