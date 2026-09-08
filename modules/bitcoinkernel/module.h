#include <bitcoinfuzz/basemodule.h>
#include <span>

namespace bitcoinfuzz {
namespace module {
class BitcoinKernel : public BaseModule {
public:
  BitcoinKernel(void);
  std::optional<std::string>
  kernel_block(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  kernel_transaction(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  kernel_block_check(std::span<const uint8_t> buffer) const override;
  // Core target to compare core's internal
  // behaviour with the public kernel ABI.
  std::optional<std::string>
  transaction_eval(std::span<const uint8_t> buffer) const override;
  ~BitcoinKernel() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
