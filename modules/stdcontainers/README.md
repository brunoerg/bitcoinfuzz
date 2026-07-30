# Standard associative containers

Provides standard-library semantic oracles for the four focused single-index
targets:

- `multi_index_ordered_unique`: `std::set`
- `multi_index_ordered_non_unique`: `std::multiset`
- `multi_index_hashed_unique`: `std::unordered_set`
- `multi_index_hashed_non_unique`: `std::unordered_multiset`

The shared operation decoder canonicalizes equal-key groups and unordered
iteration so only specified behavior is compared with Boost.MultiIndex and
tmi2.

## Build

```bash
cd modules/stdcontainers
make
```

Then compile bitcoinfuzz with `-DSTD_CONTAINERS`. For example:

```bash
FUZZ=multi_index_ordered_unique \
MODULES=BOOST_MULTI_INDEX,TMI2,STD_CONTAINERS \
./bitcoinfuzz
```
