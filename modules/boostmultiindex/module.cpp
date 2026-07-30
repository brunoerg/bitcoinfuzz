#include "module.h"

#include <bitcoinfuzz/multiindex_harness.h>
#include <bitcoinfuzz/singleindex_harness.h>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

namespace bitcoinfuzz {
namespace module {
namespace {
namespace bmi = boost::multi_index;
using Container = bmi::multi_index_container<
    multiindex::Elem,
    bmi::indexed_by<bmi::ordered_unique<multiindex::OrderedUniqueKey>,
                    bmi::hashed_unique<multiindex::HashedUniqueKey>,
                    bmi::ordered_non_unique<multiindex::NonUniqueKey>,
                    bmi::hashed_non_unique<multiindex::NonUniqueKey>>>;
using OrderedUniqueContainer = bmi::multi_index_container<
    singleindex::Elem, bmi::indexed_by<bmi::ordered_unique<singleindex::Key>>>;
using OrderedNonUniqueContainer = bmi::multi_index_container<
    singleindex::Elem,
    bmi::indexed_by<bmi::ordered_non_unique<singleindex::Key>>>;
using HashedUniqueContainer = bmi::multi_index_container<
    singleindex::Elem, bmi::indexed_by<bmi::hashed_unique<singleindex::Key>>>;
using HashedNonUniqueContainer = bmi::multi_index_container<
    singleindex::Elem,
    bmi::indexed_by<bmi::hashed_non_unique<singleindex::Key>>>;
} // namespace

BoostMultiIndex::BoostMultiIndex(void) : BaseModule("BOOST_MULTI_INDEX") {}

std::optional<std::string>
BoostMultiIndex::multiindex_ops(std::span<const uint8_t> buffer) const {
  return multiindex::RunOps<Container>(buffer);
}

std::optional<std::string>
BoostMultiIndex::ordered_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<OrderedUniqueContainer, true, true>(buffer);
}

std::optional<std::string>
BoostMultiIndex::ordered_non_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<OrderedNonUniqueContainer, true, false>(buffer);
}

std::optional<std::string>
BoostMultiIndex::hashed_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<HashedUniqueContainer, false, true>(buffer);
}

std::optional<std::string>
BoostMultiIndex::hashed_non_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<HashedNonUniqueContainer, false, false>(buffer);
}

} // namespace module
} // namespace bitcoinfuzz
