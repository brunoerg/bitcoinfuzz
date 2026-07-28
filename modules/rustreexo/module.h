#include <bitcoinfuzz/basemodule.h>
#include <optional>
#include <vector>

namespace bitcoinfuzz {
namespace module {
class Rustreexo : public BaseModule {
public:
  Rustreexo(void);

  std::optional<std::string> stump_modify_add(
      const std::vector<std::vector<uint8_t>> &add_hashes) const override;

  std::optional<std::string> stump_update(
      const std::vector<std::vector<uint8_t>> &add_hashes,
      const std::vector<std::vector<uint8_t>> &del_hashes,
      const std::vector<std::vector<uint8_t>> &new_add_hashes) const override;

  ~Rustreexo() noexcept override = default;
};
} // namespace module
} // namespace bitcoinfuzz
