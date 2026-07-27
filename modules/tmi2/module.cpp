#include "module.h"

#include <bitcoinfuzz/multiindex_harness.h>

#include <tmi.h>

namespace bitcoinfuzz {
namespace module {
namespace {
using Container = tmi::multi_index_container<
    multiindex::Elem,
    tmi::indexed_by<tmi::ordered_unique<multiindex::OrderedUniqueKey>,
                    tmi::hashed_unique<multiindex::HashedUniqueKey>,
                    tmi::ordered_non_unique<multiindex::NonUniqueKey>,
                    tmi::hashed_non_unique<multiindex::NonUniqueKey>>>;
} // namespace

Tmi2::Tmi2(void) : BaseModule("TMI2") {}

std::optional<std::string>
Tmi2::multiindex_ops(std::span<const uint8_t> buffer) const {
  return multiindex::RunOps<Container>(buffer);
}

} // namespace module
} // namespace bitcoinfuzz
