#include <bitcoinfuzz/basemodule.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace bitcoinfuzz {
namespace module {
class Btcd : public BaseModule {
public:
  Btcd(void);
  std::optional<bool>
  verify_script(const std::vector<uint8_t> &script_sig,
                const std::vector<uint8_t> &script_pubkey) const override;
  std::optional<std::string>
  deserialize_block(std::span<const uint8_t> buffer) const override;
  std::optional<std::string> address_parse(std::string str) const override;
  std::optional<std::string>
  psbt_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  addrv2_parse(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  parse_p2p_message(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  transaction_eval(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  bip32_master_keygen(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  sign_schnorr(std::span<const uint8_t> buffer, std::span<const uint8_t> hash,
               std::span<const uint8_t> aux) const override;
  std::optional<std::string>
  decode_ellswift(std::span<const uint8_t> buffer) const override;
  std::optional<std::string>
  roundtrip_ellswift(std::span<const uint8_t> privkey) const override;
  std::optional<std::string>
  schnorr_verify(std::span<const uint8_t> privkey,
                 std::span<const uint8_t> hash,
                 std::span<const uint8_t> sign) const override;
  std::optional<std::string> bip32_deserialize_extended_key(
      std::span<const uint8_t> buffer) const override;
  std::optional<std::string> merkle_root_compute(
      const std::vector<std::vector<uint8_t>> &hashes) const override;
  std::optional<std::string>
  bech32_segwit_roundtrip(const Bech32SegwitInput &input) const override;
  std::optional<std::string>
  bech32_convert_bits(const Bech32ConvertBitsInput &input) const override;
  ~Btcd() noexcept override = default;
};

} // namespace module
} // namespace bitcoinfuzz
