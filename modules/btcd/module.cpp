#include <cstring>
#include <span>

#include "btcd_wrapper/libbtcd_wrapper.h"
#include "module.h"

namespace bitcoinfuzz {
namespace module {
Btcd::Btcd(void) : BaseModule("Btcd") {}

std::optional<bool>
Btcd::verify_script(const std::vector<uint8_t> &script_sig,
                    const std::vector<uint8_t> &script_pubkey) const {
  ByteArray script_data{.data = reinterpret_cast<char *>(
                            const_cast<uint8_t *>(script_sig.data())),
                        .length = static_cast<int>(script_sig.size())};

  ByteArray script_data2{.data = reinterpret_cast<char *>(
                             const_cast<uint8_t *>(script_pubkey.data())),
                         .length = static_cast<int>(script_pubkey.size())};

  return BTCDVerifyScript(script_data, script_data2) == 1;
}

std::optional<std::string>
Btcd::parse_p2p_message(std::span<const uint8_t> buffer) const {
  ByteArray message_data{
      .data = reinterpret_cast<char *>(const_cast<uint8_t *>(buffer.data())),
      .length = static_cast<int>(buffer.size())};

  const auto message_res = BTCDParseP2PMessage(message_data);

  if (message_res == nullptr) {
    return std::nullopt;
  }
  if (strlen(message_res) == 0) {
    free(message_res);
    return std::nullopt;
  }

  std::string res(message_res);
  free(message_res);
  return res;
}

std::optional<std::string>
Btcd::deserialize_block(std::span<const uint8_t> buffer) const {
  ByteArray script_data{
      .data = reinterpret_cast<char *>(const_cast<uint8_t *>(buffer.data())),
      .length = static_cast<int>(buffer.size())};

  auto pointer{BTCDDesBlock(script_data)};
  std::string result(pointer);
  BTCDFreeString(pointer);
  if (result == "unsupported segwit version") {
    return std::nullopt;
  }
  return result;
}

std::optional<std::string>
Btcd::addrv2_parse(std::span<const uint8_t> buffer) const {
  ByteArray addrv2;
  addrv2.data = (char *)buffer.data();
  addrv2.length = buffer.size();

  char *result = BTCDAddrv2(addrv2);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string>
Btcd::psbt_parse(std::span<const uint8_t> buffer) const {
  ByteArray script;
  script.data = (char *)buffer.data();
  script.length = buffer.size();

  char *result = BTCDParsePSBT(script);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string> Btcd::address_parse(std::string str) const {
  ByteArray data;
  data.data = const_cast<char *>(str.data());
  data.length = static_cast<int>(str.size());

  char *result = BTCDAddress(data);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string>
Btcd::transaction_eval(std::span<const uint8_t> buffer) const {
  ByteArray tx;
  tx.data = (char *)buffer.data();
  tx.length = buffer.size();

  char *result = BTCDTransactionEval(tx);

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string> Btcd::merkle_root_compute(
    const std::vector<std::vector<uint8_t>> &hashes) const {
  // Flatten the 32-byte hashes into a single buffer for the FFI call.
  std::vector<uint8_t> flat;
  flat.reserve(hashes.size() * 32);
  for (const auto &hash : hashes) {
    if (hash.size() != 32)
      return std::nullopt;
    flat.insert(flat.end(), hash.begin(), hash.end());
  }

  ByteArray data{.data = reinterpret_cast<char *>(flat.data()),
                 .length = static_cast<int>(flat.size())};

  char *result = BTCDMerkleRootCompute(data);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string>
Btcd::sighash_compute(const SighashComputeInput &input) const {
  auto to_byte_array = [](const std::vector<uint8_t> &v) {
    return ByteArray{
        .data = reinterpret_cast<char *>(const_cast<uint8_t *>(v.data())),
        .length = static_cast<int>(v.size())};
  };

  char *result = BTCDSighashCompute(
      to_byte_array(input.tx_bytes), to_byte_array(input.script),
      to_byte_array(input.sig_to_delete), input.input_index, input.n_codesep,
      input.amount, input.sighash_type, input.is_segwit_v0 ? 1 : 0);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}
std::optional<std::string>
Btcd::bip32_master_keygen(std::span<const uint8_t> buffer) const {
  ByteArray seed;
  seed.data = (char *)buffer.data();
  seed.length = buffer.size();

  char *result = BTCDBip32MasterKeygen(seed);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string>
Btcd::sign_schnorr(std::span<const uint8_t> buffer,
                   std::span<const uint8_t> hash,
                   std::span<const uint8_t> aux) const {
  ByteArray privKey;
  privKey.data = (char *)buffer.data();
  privKey.length = buffer.size();

  ByteArray msgHash;
  msgHash.data = (char *)hash.data();
  msgHash.length = hash.size();

  ByteArray auxData;
  auxData.data = reinterpret_cast<char *>(const_cast<uint8_t *>(aux.data()));
  auxData.length = aux.size();

  char *result = BTCDSignSchnorr(privKey, msgHash, auxData);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string>
Btcd::roundtrip_ellswift(std::span<const uint8_t> privkey) const {
  ByteArray key;
  key.data = (char *)privkey.data();
  key.length = privkey.size();

  char *result = BTCDRoundtripEllswift(key);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string>
Btcd::decode_ellswift(std::span<const uint8_t> buffer) const {
  ByteArray ell;
  ell.data = (char *)buffer.data();
  ell.length = buffer.size();

  char *result = BTCDDecodeEllswift(ell);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string>
Btcd::schnorr_verify(std::span<const uint8_t> privkey_bytes,
                     std::span<const uint8_t> hash,
                     std::span<const uint8_t> sig) const {
  ByteArray privkey;
  privkey.data = (char *)privkey_bytes.data();
  privkey.length = privkey_bytes.size();

  ByteArray msgHash;
  msgHash.data = (char *)hash.data();
  msgHash.length = hash.size();

  ByteArray signature;
  signature.data = (char *)sig.data();
  signature.length = sig.size();

  char *result = BTCDSchnorrVerify(privkey, msgHash, signature);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

std::optional<std::string>
Btcd::bip32_deserialize_extended_key(std::span<const uint8_t> buffer) const {
  ByteArray data;
  data.data = (char *)buffer.data();
  data.length = buffer.size();
  char *result = BTCDBip32DeserializeExtendedKey(data);
  if (!result)
    return std::nullopt;

  std::string res(result);
  BTCDFreeString(result);
  return res;
}

} // namespace module
} // namespace bitcoinfuzz
