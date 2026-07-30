#!/usr/bin/env bash
set -euo pipefail

BASE_SHA="${1:-}"
HEAD_SHA="${2:-}"

# -w: whitespace-only churn must not pull a module into the build.
CHANGED_FILES="$(git diff -w --name-only "$BASE_SHA" "$HEAD_SHA")"

declare -A MODULE_FLAGS=(
  [bitcoin]="-DBITCOIN_CORE"
  [rustbitcoin]="-DRUST_BITCOIN"
  [rustpsbt]="-DRUST_PSBT"
  [rustminiscript]="-DRUST_MINISCRIPT"
  [tinyminiscript]="-DTINY_MINISCRIPT"
  [bitcoinerlabminiscript]="-DBITCOINERLAB_MINISCRIPT"
  [btcd]="-DBTCD"
  [gocoin]="-DGOCOIN"
  [nbitcoin]="-DNBITCOIN"
  [lnd]="-DLND"
  [ldk]="-DLDK"
  [eclair]="-DECLAIR"
  [nlightning]="-DNLIGHTNING"
  [embit]="-DEMBIT"
  [pybitcoinkernel]="-DPYBITCOINKERNEL"
  [rustbitcoinkernel]="-DRUSTBITCOINKERNEL"
  [bitcoinkernel]="-DBITCOINKERNEL"
  [bitcoinkernelvariant]="-DBITCOINKERNEL_VARIANT"
  [clightning]="-DCLIGHTNING"
  [lightningkmp]="-DLIGHTNING_KMP"
  [bitcoinj]="-DBITCOINJ"
  [bitcoins]="-DBITCOINS"
  [decredsecp256k1]="-DDECRED_SECP256K1"
  [secp256k1]="-DSECP256K1"
  [nbitcoinsecp256k1]="-DNBITCOIN_SECP256K1"
  [rustk256]="-DRUST_K256"
  [libwallycore]="-DLIBWALLY_CORE"
  [rustmusig2]="-DRUST_MUSIG2"
  [rustcryptoaes]="-DRUSTCRYPTO_AES"
  [rustreexo]="-DRUSTREEXO"
  [utreexo]="-DUTREEXO"
  [pycoin]="-DPYCOIN"
  [libbitcoinsystem]="-DLIBBITCOIN_SYSTEM"
  [boostmultiindex]="-DBOOST_MULTI_INDEX"
  [tmi2]="-DTMI2"
  [stdcontainers]="-DSTD_CONTAINERS"
)

mapfile -t MODULES < <(
  echo "$CHANGED_FILES" \
    | awk -F/ '/^modules\/[^/]+\// { print $2 }' \
    | sort -u
)

# If no modules were changed, default to bitcoin and rustbitcoin
DEFAULT_FLAGS="-DBITCOIN_CORE -DRUST_BITCOIN"
DEFAULT_SELECTED_MODULES="fallback: bitcoin,rustbitcoin"

if [ "${#MODULES[@]}" -eq 0 ]; then
  CXXFLAGS="$DEFAULT_FLAGS"
  SELECTED_MODULES="$DEFAULT_SELECTED_MODULES"
else
  FLAGS=()
  for module in "${MODULES[@]}"; do
    if [ -z "${MODULE_FLAGS[$module]:-}" ]; then
      echo "::error::No CXXFLAG mapping configured for module '$module'"
      exit 1
    fi
    FLAGS+=("${MODULE_FLAGS[$module]}")
  done
  CXXFLAGS="${FLAGS[*]}"
  SELECTED_MODULES="$(IFS=,; echo "${MODULES[*]}")"
fi

echo "Selected modules: $SELECTED_MODULES" >&2
echo "Resolved CXXFLAGS: $CXXFLAGS" >&2
echo "cxxflags=$CXXFLAGS"
