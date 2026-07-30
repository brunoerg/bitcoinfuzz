#pragma once

#include <fuzzer/FuzzedDataProvider.h>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <span>
#include <string>
#include <tuple>
#include <vector>

namespace bitcoinfuzz {
namespace singleindex {

struct Elem {
  uint16_t key;
  uint16_t value;
};

struct Key {
  using result_type = uint16_t;
  result_type operator()(const Elem &e) const { return e.key; }
};

inline void AppendElem(std::string &trace, const Elem &e) {
  trace += std::to_string(e.key);
  trace += '.';
  trace += std::to_string(e.value);
  trace += ';';
}

template <typename Iterator>
void AppendCanonicalRange(std::string &trace, Iterator first, Iterator last) {
  std::vector<Elem> values(first, last);
  std::ranges::sort(values, [](const Elem &a, const Elem &b) {
    return std::tie(a.key, a.value) < std::tie(b.key, b.value);
  });
  trace += '[';
  for (const Elem &e : values)
    AppendElem(trace, e);
  trace += ']';
}

template <typename Container>
void AppendCanonicalMatches(std::string &trace, const Container &c,
                            uint16_t key) {
  std::vector<Elem> values;
  for (const Elem &e : c) {
    if (e.key == key)
      values.push_back(e);
  }
  AppendCanonicalRange(trace, values.begin(), values.end());
}

template <bool Ordered, typename Container>
void AppendState(std::string &trace, const Container &c) {
  trace += "S:";
  trace += std::to_string(c.size());
  trace += c.empty() ? "e" : "n";
  if constexpr (Ordered) {
    trace += std::ranges::is_sorted(c, {}, &Elem::key) ? "T" : "F";
  }
  AppendCanonicalRange(trace, c.begin(), c.end());
}

// tmi2's single-index containers use the same broken clear implementation as
// its multi-index containers: nodes are removed but m_size is not reset.
inline constexpr bool kEnableClearOps = false;

// A full state dump costs O(n log n), so dumping after every op makes an
// input quadratic in its op count (a random 32 KiB input spent ~21 s and
// ~700 MB building traces). Per-op the trace records only the size; the full
// canonical state is dumped every kStateDumpInterval ops and once at the end,
// which still pins a content divergence to a window of at most
// kStateDumpInterval ops.
inline constexpr size_t kStateDumpInterval = 16;

// Runs operations common to a one-index Boost.MultiIndex/tmi2 container and
// the matching std associative container adapter. Results and contents are
// canonicalized whenever an index does not specify iteration order.
template <typename Container, bool Ordered, bool Unique>
std::string RunOps(std::span<const uint8_t> buffer) {
  FuzzedDataProvider fdp(buffer.data(), buffer.size());
  Container c;
  std::string trace;
  size_t op_count = 0;

  while (fdp.remaining_bytes() > 0) {
    uint8_t op = fdp.ConsumeIntegralInRange<uint8_t>(0, 7);
    trace += '|';
    switch (op) {
    case 0:
    case 1: {
      Elem e{fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint16_t>()};
      if constexpr (Unique) {
        auto [it, inserted] = c.insert(e);
        trace += inserted ? "i1" : "i0";
        AppendElem(trace, *it);
      } else {
        auto result = c.insert(e);
        trace += 'i';
        if constexpr (requires { result.first; })
          AppendElem(trace, *result.first);
        else
          AppendElem(trace, *result);
      }
      break;
    }
    case 2: {
      Elem e{fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint16_t>()};
      if constexpr (Unique) {
        auto [it, inserted] = c.emplace(e);
        trace += inserted ? "p1" : "p0";
        AppendElem(trace, *it);
      } else {
        auto result = c.emplace(e);
        trace += 'p';
        if constexpr (requires { result.first; })
          AppendElem(trace, *result.first);
        else
          AppendElem(trace, *result);
      }
      break;
    }
    case 3: {
      uint16_t key = fdp.ConsumeIntegral<uint16_t>();
      auto it = c.find(key);
      trace += it == c.end() ? "f0" : "f1";
      if constexpr (Unique) {
        if (it != c.end())
          AppendElem(trace, *it);
      }
      trace += 'c';
      trace += std::to_string(c.count(key));
      if constexpr (Ordered) {
        auto [first, last] = c.equal_range(key);
        AppendCanonicalRange(trace, first, last);
      } else {
        AppendCanonicalMatches(trace, c, key);
      }
      break;
    }
    case 4: {
      uint16_t key = fdp.ConsumeIntegral<uint16_t>();
      trace += 'E';
      if constexpr (Ordered) {
        trace += std::to_string(c.erase(key));
      } else {
        size_t erased = 0;
        for (auto it = c.begin(); it != c.end();) {
          if (it->key == key) {
            it = c.erase(it);
            ++erased;
          } else {
            ++it;
          }
        }
        trace += std::to_string(erased);
      }
      break;
    }
    case 5: {
      Elem requested{fdp.ConsumeIntegral<uint16_t>(),
                     fdp.ConsumeIntegral<uint16_t>()};
      auto it = std::find_if(c.begin(), c.end(), [&](const Elem &e) {
        return std::tie(e.key, e.value) ==
               std::tie(requested.key, requested.value);
      });
      if (it == c.end()) {
        trace += "e0";
      } else {
        trace += "e1";
        AppendElem(trace, *it);
        c.erase(it);
      }
      break;
    }
    case 6: {
      uint16_t key = fdp.ConsumeIntegral<uint16_t>();
      if constexpr (Ordered) {
        trace += 'l';
        auto lower = c.lower_bound(key);
        if (lower == c.end())
          trace += '$';
        else
          trace += std::to_string(lower->key);

        trace += 'u';
        auto upper = c.upper_bound(key);
        if (upper == c.end())
          trace += '$';
        else
          trace += std::to_string(upper->key);
      } else {
        trace += 'q';
        trace += std::to_string(c.count(key));
        AppendCanonicalMatches(trace, c, key);
      }
      break;
    }
    case 7: {
      if ((fdp.ConsumeIntegral<uint8_t>() & 0x1f) == 0) {
        if constexpr (kEnableClearOps) {
          c.clear();
          trace += 'x';
        }
      }
      break;
    }
    }

    trace += 's';
    trace += std::to_string(c.size());
    if (++op_count % kStateDumpInterval == 0)
      AppendState<Ordered>(trace, c);
  }

  AppendState<Ordered>(trace, c);
  return trace;
}

} // namespace singleindex
} // namespace bitcoinfuzz
