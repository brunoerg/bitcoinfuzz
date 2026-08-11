#pragma once

#include <bitcoinfuzz/basemodule.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace bitcoinfuzz {
namespace module {

class Gocoin : public BaseModule {
public:
  Gocoin(void);

  std::optional<bool>
  verify_script(const std::vector<uint8_t> &script_sig,
                const std::vector<uint8_t> &script_pubkey) const override;
  std::optional<bool> script_eval(const std::vector<uint8_t> &input_data,
                                  unsigned int flags,
                                  size_t version) const override;
  std::optional<std::string> merkle_root_compute(
      const std::vector<std::vector<uint8_t>> &hashes) const override;
  std::optional<std::string>
  sighash_compute(const SighashComputeInput &input) const override;

  ~Gocoin() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
