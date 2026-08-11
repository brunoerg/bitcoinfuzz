#include <bitcoinfuzz/basemodule.h>
#include <optional>
#include <span>

namespace bitcoinfuzz {
namespace module {
class RustMusig2 : public BaseModule {
public:
  RustMusig2(void);
  std::optional<std::string>
  musig2_key_agg(std::span<const uint8_t> seckeys) const override;
  std::optional<std::string>
  musig2_sign_session(const Musig2SignSessionInput &input) const override;
  std::optional<std::string>
  musig2_keyagg_ctx(std::span<const uint8_t> buffer) const override;
  ~RustMusig2() noexcept override = default;
};
} // namespace module
} // namespace bitcoinfuzz
