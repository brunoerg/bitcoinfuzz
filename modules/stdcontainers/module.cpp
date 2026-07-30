#include "module.h"

#include <bitcoinfuzz/singleindex_harness.h>

#include <set>
#include <type_traits>
#include <unordered_set>

namespace bitcoinfuzz {
namespace module {
namespace {
using Elem = singleindex::Elem;

struct KeyLess {
  using is_transparent = void;
  bool operator()(const Elem &a, const Elem &b) const { return a.key < b.key; }
  bool operator()(const Elem &a, uint16_t b) const { return a.key < b; }
  bool operator()(uint16_t a, const Elem &b) const { return a < b.key; }
};

struct KeyHash {
  using is_transparent = void;
  size_t operator()(const Elem &e) const {
    return std::hash<uint16_t>{}(e.key);
  }
  size_t operator()(uint16_t key) const { return std::hash<uint16_t>{}(key); }
};

struct KeyEqual {
  using is_transparent = void;
  bool operator()(const Elem &a, const Elem &b) const { return a.key == b.key; }
  bool operator()(const Elem &a, uint16_t b) const { return a.key == b; }
  bool operator()(uint16_t a, const Elem &b) const { return a == b.key; }
};

template <bool Ordered, bool Unique> class StdIndex {
  using OrderedStorage = std::conditional_t<Unique, std::set<Elem, KeyLess>,
                                            std::multiset<Elem, KeyLess>>;
  using HashedStorage =
      std::conditional_t<Unique, std::unordered_set<Elem, KeyHash, KeyEqual>,
                         std::unordered_multiset<Elem, KeyHash, KeyEqual>>;
  using Storage = std::conditional_t<Ordered, OrderedStorage, HashedStorage>;

  Storage data;

public:
  auto begin() { return data.begin(); }
  auto begin() const { return data.begin(); }
  auto end() { return data.end(); }
  auto end() const { return data.end(); }
  size_t size() const { return data.size(); }
  bool empty() const { return data.empty(); }
  void clear() { data.clear(); }

  auto insert(const Elem &e) { return data.insert(e); }
  auto emplace(const Elem &e) { return data.emplace(e); }
  auto find(uint16_t key) { return data.find(key); }
  auto count(uint16_t key) const { return data.count(key); }
  auto equal_range(uint16_t key) { return data.equal_range(key); }
  auto erase(typename Storage::iterator it) { return data.erase(it); }

  size_t erase(uint16_t key) {
    auto [first, last] = data.equal_range(key);
    size_t erased = std::distance(first, last);
    data.erase(first, last);
    return erased;
  }

  auto lower_bound(uint16_t key)
    requires Ordered
  {
    return data.lower_bound(key);
  }
  auto upper_bound(uint16_t key)
    requires Ordered
  {
    return data.upper_bound(key);
  }
};

using OrderedUnique = StdIndex<true, true>;
using OrderedNonUnique = StdIndex<true, false>;
using HashedUnique = StdIndex<false, true>;
using HashedNonUnique = StdIndex<false, false>;
} // namespace

StdContainers::StdContainers(void) : BaseModule("STD_CONTAINERS") {}

std::optional<std::string>
StdContainers::ordered_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<OrderedUnique, true, true>(buffer);
}

std::optional<std::string>
StdContainers::ordered_non_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<OrderedNonUnique, true, false>(buffer);
}

std::optional<std::string>
StdContainers::hashed_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<HashedUnique, false, true>(buffer);
}

std::optional<std::string>
StdContainers::hashed_non_unique_ops(std::span<const uint8_t> buffer) const {
  return singleindex::RunOps<HashedNonUnique, false, false>(buffer);
}

} // namespace module
} // namespace bitcoinfuzz
