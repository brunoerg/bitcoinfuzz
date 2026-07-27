#include "module.h"

#include <bitcoinfuzz/multiindex_harness.h>

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
} // namespace

BoostMultiIndex::BoostMultiIndex(void) : BaseModule("BOOST_MULTI_INDEX") {}

std::optional<std::string>
BoostMultiIndex::multiindex_ops(std::span<const uint8_t> buffer) const {
  return multiindex::RunOps<Container>(buffer);
}

} // namespace module
} // namespace bitcoinfuzz
