#include "module.h"
#include "utreexo_wrapper/libutreexo_wrapper.h"
#include <vector>

namespace bitcoinfuzz {
namespace module {
Utreexo::Utreexo(void) : BaseModule("Utreexo") {}

std::optional<std::string> Utreexo::stump_modify_add(
    const std::vector<std::vector<uint8_t>> &add_hashes) const {
  std::vector<uint8_t> flat;
  flat.reserve(add_hashes.size() * 32);
  for (const auto &hash : add_hashes)
    flat.insert(flat.end(), hash.begin(), hash.end());

  ByteArray leaf_hashes{.data = reinterpret_cast<char *>(flat.data()),
                        .length = static_cast<int>(flat.size())};

  auto result = UtreexoStumpUpdate(leaf_hashes);
  if (!result)
    return std::nullopt;
  std::string result_str(result);
  free(result);
  return result_str;
}

namespace {
std::vector<uint8_t>
FlattenHashes(const std::vector<std::vector<uint8_t>> &hashes) {
  std::vector<uint8_t> flat;
  flat.reserve(hashes.size() * 32);
  for (const auto &hash : hashes)
    flat.insert(flat.end(), hash.begin(), hash.end());
  return flat;
}
} // namespace

std::optional<std::string> Utreexo::stump_update(
    const std::vector<std::vector<uint8_t>> &add_hashes,
    const std::vector<std::vector<uint8_t>> &del_hashes,
    const std::vector<std::vector<uint8_t>> &new_add_hashes) const {
  std::vector<uint8_t> adds{FlattenHashes(add_hashes)};
  std::vector<uint8_t> dels{FlattenHashes(del_hashes)};
  std::vector<uint8_t> new_adds{FlattenHashes(new_add_hashes)};

  ByteArray adds_arr{.data = reinterpret_cast<char *>(adds.data()),
                     .length = static_cast<int>(adds.size())};
  ByteArray dels_arr{.data = reinterpret_cast<char *>(dels.data()),
                     .length = static_cast<int>(dels.size())};
  ByteArray new_adds_arr{.data = reinterpret_cast<char *>(new_adds.data()),
                         .length = static_cast<int>(new_adds.size())};

  auto result = UtreexoStumpUpdateWithDels(adds_arr, dels_arr, new_adds_arr);
  if (!result)
    return std::nullopt;
  std::string result_str(result);
  free(result);
  return result_str;
}
} // namespace module
} // namespace bitcoinfuzz
