#include "module.h"

#include <bitcoinfuzz/multiindex_harness.h>
#include <bitcoinfuzz/singleindex_harness.h>

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
using OrderedUniqueContainer = tmi::multi_index_container<
    singleindex::Elem, tmi::indexed_by<tmi::ordered_unique<singleindex::Key>>>;
using OrderedNonUniqueContainer = tmi::multi_index_container<
    singleindex::Elem,
    tmi::indexed_by<tmi::ordered_non_unique<singleindex::Key>>>;
using HashedUniqueContainer = tmi::multi_index_container<
    singleindex::Elem, tmi::indexed_by<tmi::hashed_unique<singleindex::Key>>>;
using HashedNonUniqueContainer = tmi::multi_index_container<
    singleindex::Elem,
    tmi::indexed_by<tmi::hashed_non_unique<singleindex::Key>>>;
} // namespace

Tmi2::Tmi2(void) : BaseModule("TMI2") {}

std::optional<std::string>
Tmi2::multiindex_ops(std::span<const uint8_t> buffer) const {
  return multiindex::RunOps<Container>(buffer);
}

std::optional<std::string>
Tmi2::ordered_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<OrderedUniqueContainer, true, true>(buffer);
}

std::optional<std::string>
Tmi2::ordered_non_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<OrderedNonUniqueContainer, true, false>(buffer);
}

std::optional<std::string>
Tmi2::hashed_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<HashedUniqueContainer, false, true>(buffer);
}

std::optional<std::string>
Tmi2::hashed_non_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<HashedNonUniqueContainer, false, false>(buffer);
}

} // namespace module
} // namespace bitcoinfuzz
