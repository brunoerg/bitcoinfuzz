#pragma once

#include <fuzzer/FuzzedDataProvider.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <span>
#include <string>
#include <vector>

namespace bitcoinfuzz {
namespace multiindex {

// Element and key extractors shared by every multi_index implementation under
// test. The extractors satisfy both Boost's KeyFromValue concept and tmi's, so
// the same types instantiate boost::multi_index_container and
// tmi::multi_index_container.
struct Elem {
  uint16_t ordered_unique;
  uint16_t hashed_unique;
  uint8_t non_unique;
};

struct OrderedUniqueKey {
  using result_type = uint16_t;
  result_type operator()(const Elem &e) const { return e.ordered_unique; }
};
struct HashedUniqueKey {
  using result_type = uint16_t;
  result_type operator()(const Elem &e) const { return e.hashed_unique; }
};
struct NonUniqueKey {
  using result_type = uint8_t;
  result_type operator()(const Elem &e) const { return e.non_unique; }
};

// Both flags gate known tmi2 divergences so the target stays useful for the
// remaining ops until the upstream fixes land. The op decoding consumes the
// same bytes either way, so existing corpora stay valid when they are
// re-enabled.
//
// kEnableModifyOps: tmi::do_modify does not compile (tmi.h:422 passes the
// node pointer to tmi_preinsert_node, which takes const value_type&), and
// with that fixed, a modify that collides on another index's unique key
// keeps both elements where Boost erases the modified one.
//
// kEnableClearOps: tmi::do_clear does not reset m_size, so size()/empty()
// report stale values after clear().
inline constexpr bool kEnableModifyOps = false;
inline constexpr bool kEnableClearOps = false;

inline void AppendElem(std::string &trace, const Elem &e) {
  trace += std::to_string(e.ordered_unique);
  trace += '.';
  trace += std::to_string(e.hashed_unique);
  trace += '.';
  trace += std::to_string(e.non_unique);
  trace += ';';
}

// Records everything implementation-independent about the container: sizes of
// all four views, full iteration of the ordered_unique index (its order is a
// contract), whether the ordered_non_unique index iterates in non-decreasing
// key order, and its contents canonicalized within equal-key runs. The
// relative order of equivalent elements in a non-unique index and the
// iteration order of hashed indices are not contracts, so they stay out of the
// trace.
template <typename Container>
void AppendState(std::string &trace, const Container &c) {
  const auto &ordered_unique_view = c.template get<0>();
  const auto &hashed_unique_view = c.template get<1>();
  const auto &ordered_nonunique_view = c.template get<2>();
  const auto &hashed_nonunique_view = c.template get<3>();

  trace += "S:";
  trace += std::to_string(ordered_unique_view.size());
  trace += ',';
  trace += std::to_string(hashed_unique_view.size());
  trace += ',';
  trace += std::to_string(ordered_nonunique_view.size());
  trace += ',';
  trace += std::to_string(hashed_nonunique_view.size());
  trace += ordered_unique_view.empty() ? "e" : "n";

  trace += '[';
  for (const Elem &e : ordered_unique_view)
    AppendElem(trace, e);
  trace += "][";

  std::vector<Elem> nonunique(ordered_nonunique_view.begin(),
                              ordered_nonunique_view.end());
  trace += std::ranges::is_sorted(nonunique, {}, &Elem::non_unique) ? "T" : "F";
  std::sort(nonunique.begin(), nonunique.end(),
            [](const Elem &a, const Elem &b) {
              return std::tie(a.non_unique, a.ordered_unique) <
                     std::tie(b.non_unique, b.ordered_unique);
            });
  for (const Elem &e : nonunique)
    AppendElem(trace, e);
  trace += ']';
}

// Decodes the fuzz buffer into a deterministic op sequence, applies it to a
// fresh Container and returns a trace of every observable outcome. The driver
// compares traces across implementations; any divergence aborts the fuzzer.
template <typename Container>
std::string RunOps(std::span<const uint8_t> buffer) {
  FuzzedDataProvider fdp(buffer.data(), buffer.size());
  Container c;
  auto &ordered_unique_view = c.template get<0>();
  auto &hashed_unique_view = c.template get<1>();
  auto &ordered_nonunique_view = c.template get<2>();
  auto &hashed_nonunique_view = c.template get<3>();

  std::string trace;

  while (fdp.remaining_bytes() > 0) {
    uint8_t op = fdp.ConsumeIntegralInRange<uint8_t>(0, 9);
    trace += '|';
    switch (op) {
    case 0:
    case 1: { // insert via ordered_unique view
      Elem e{fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint16_t>(),
             fdp.ConsumeIntegral<uint8_t>()};
      auto [it, inserted] = ordered_unique_view.insert(e);
      trace += inserted ? "i1" : "i0";
      AppendElem(trace, *it);
      break;
    }
    case 2: { // emplace via hashed_unique view
      Elem e{fdp.ConsumeIntegral<uint16_t>(), fdp.ConsumeIntegral<uint16_t>(),
             fdp.ConsumeIntegral<uint8_t>()};
      auto [it, inserted] = hashed_unique_view.emplace(e);
      trace += inserted ? "p1" : "p0";
      AppendElem(trace, *it);
      break;
    }
    case 3: { // erase via ordered_unique find
      uint16_t ou = fdp.ConsumeIntegral<uint16_t>();
      auto it = ordered_unique_view.find(ou);
      if (it != ordered_unique_view.end()) {
        trace += "e1";
        AppendElem(trace, *it);
        ordered_unique_view.erase(it);
      } else {
        trace += "e0";
      }
      break;
    }
    case 4: { // erase via hashed_unique find
      uint16_t hu = fdp.ConsumeIntegral<uint16_t>();
      auto it = hashed_unique_view.find(hu);
      if (it != hashed_unique_view.end()) {
        trace += "h1";
        AppendElem(trace, *it);
        hashed_unique_view.erase(it);
      } else {
        trace += "h0";
      }
      break;
    }
    case 5: { // erase every element matching a non-unique key
      uint8_t nu = fdp.ConsumeIntegral<uint8_t>();
      size_t erased = ordered_nonunique_view.erase(nu);
      trace += 'E';
      trace += std::to_string(erased);
      break;
    }
    case 6: { // lookups across all four views
      uint16_t ou = fdp.ConsumeIntegral<uint16_t>();
      uint8_t nu = fdp.ConsumeIntegral<uint8_t>();

      auto it = ordered_unique_view.find(ou);
      if (it != ordered_unique_view.end()) {
        trace += "f1";
        AppendElem(trace, *it);
      } else {
        trace += "f0";
      }
      trace += std::to_string(ordered_unique_view.count(ou));
      trace += ',';
      trace += std::to_string(hashed_unique_view.count(ou));
      trace += ',';
      trace += std::to_string(ordered_nonunique_view.count(nu));
      trace += ',';
      trace += std::to_string(hashed_nonunique_view.count(nu));

      auto [first, last] = ordered_nonunique_view.equal_range(nu);
      trace += 'r';
      trace += std::to_string(std::distance(first, last));

      auto lb = ordered_unique_view.lower_bound(ou);
      if (lb != ordered_unique_view.end())
        AppendElem(trace, *lb);
      else
        trace += '$';
      break;
    }
    case 7: { // modify via ordered_unique view
      uint16_t target = fdp.ConsumeIntegral<uint16_t>();
      Elem repl{fdp.ConsumeIntegral<uint16_t>(),
                fdp.ConsumeIntegral<uint16_t>(),
                fdp.ConsumeIntegral<uint8_t>()};
      if constexpr (kEnableModifyOps) {
        auto it = ordered_unique_view.find(target);
        if (it == ordered_unique_view.end()) {
          trace += "m-";
          break;
        }
        bool modified =
            ordered_unique_view.modify(it, [&](Elem &e) { e = repl; });
        trace += modified ? "m1" : "m0";
      }
      break;
    }
    case 8: { // modify via hashed_unique view
      uint16_t target = fdp.ConsumeIntegral<uint16_t>();
      Elem repl{fdp.ConsumeIntegral<uint16_t>(),
                fdp.ConsumeIntegral<uint16_t>(),
                fdp.ConsumeIntegral<uint8_t>()};
      if constexpr (kEnableModifyOps) {
        auto it = hashed_unique_view.find(target);
        if (it == hashed_unique_view.end()) {
          trace += "M-";
          break;
        }
        bool modified =
            hashed_unique_view.modify(it, [&](Elem &e) { e = repl; });
        trace += modified ? "M1" : "M0";
      }
      break;
    }
    case 9: { // clear (rarely, to exercise teardown mid-stream)
      if ((fdp.ConsumeIntegral<uint8_t>() & 0x1f) == 0) {
        if constexpr (kEnableClearOps) {
          ordered_unique_view.clear();
          trace += 'c';
        }
      }
      break;
    }
    }

    // Per-op size keeps a divergence localized to the op that caused it.
    trace += 's';
    trace += std::to_string(ordered_unique_view.size());
  }

  AppendState(trace, c);
  return trace;
}

} // namespace multiindex
} // namespace bitcoinfuzz
