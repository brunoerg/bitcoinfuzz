#include <bitcoinfuzz/basemodule.h>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace bitcoinfuzz {
namespace module {
class BoostMultiIndex : public BaseModule {
public:
  BoostMultiIndex(void);
  std::optional<std::string>
  multiindex_ops(std::span<const uint8_t> buffer) const override;
  ~BoostMultiIndex() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
