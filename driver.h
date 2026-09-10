#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <bitcoinfuzz/basemodule.h>
#include <bitcoinfuzz/modulelogger.h>

namespace bitcoinfuzz {
class Driver {
private:
  ModuleLogger &module_logger;
  std::map<std::string, std::shared_ptr<BaseModule>> modules;
  bool log_outputs;

  template <typename T>
  void LogResponse(const std::string &module_name, const T &response) const;

  template <typename T>
  void VerifyMatchingResponse(std::optional<T> &last_response,
                              std::string &last_module_name,
                              const std::string &module_name, const T &response,
                              std::string_view failure_message) const;

public:
  Driver(ModuleLogger &logger, bool log_outputs = false)
      : module_logger(logger), log_outputs(log_outputs) {}
  void LoadModule(std::shared_ptr<BaseModule> module);
  void ScriptTarget(std::span<const uint8_t>) const;
  void ScriptEvalTarget(std::span<const uint8_t> buffer) const;
  void VerifyScriptTarget(std::span<const uint8_t> buffer) const;
  void BlockDeserializationTarget(std::span<const uint8_t> buffer) const;
  void DescriptorParseTarget(std::span<const uint8_t> buffer) const;
  void MiniscriptParseTarget(std::span<const uint8_t> buffer) const;
  void InvoiceDeserializationTarget(std::span<const uint8_t> buffer) const;
  void Run(const uint8_t *data, const size_t size,
           const std::string &target) const;
  void AddressParseTarget(std::span<const uint8_t> buffer) const;
  void PSBTParseTarget(std::span<const uint8_t> buffer) const;
  void AddrV2Target(std::span<const uint8_t> buffer) const;
  void OfferDeserializationTarget(std::span<const uint8_t> buffer) const;
  void CompactBlocksTarget(std::span<const uint8_t> buffer) const;
  void ParseP2PMessageTarget(std::span<const uint8_t> buffer) const;
  void ParseLightningP2pMessageTarget(std::span<const uint8_t> buffer) const;
  void TransactionEvalTarget(std::span<const uint8_t> buffer) const;
  void Bip32MasterKeygenTarget(std::span<const uint8_t> buffer) const;
  void KernelBlockTarget(std::span<const uint8_t> buffer) const;
  void KernelTransactionTarget(std::span<const uint8_t> buffer) const;
  void KernelBlockCheckTarget(std::span<const uint8_t> buffer) const;
  void PrivateToPublicKeyTarget(std::span<const uint8_t> buffer) const;
  void PubkeyParseTarget(std::span<const uint8_t> buffer) const;
  void SignCompactTarget(std::span<const uint8_t> buffer) const;
  void SignDerTarget(std::span<const uint8_t> buffer) const;
  void SignVerifyTarget(std::span<const uint8_t> buffer) const;
  void ECDHTarget(std::span<const uint8_t> buffer) const;
  void SignSchnorrTarget(std::span<const uint8_t> buffer) const;
  void Bip32DeserializeExtendedKeyTarget(std::span<const uint8_t> buffer) const;
  void DecodeEllswiftTarget(std::span<const uint8_t> buffer) const;
  void EllswiftRoundTripXTarget(std::span<const uint8_t> buffer) const;
  void SchnorrVerifyTarget(std::span<const uint8_t> buffer) const;
  void DecodeOnionTarget(std::span<const uint8_t> buffer) const;
  void StumpModifyAddTarget(std::span<const uint8_t> buffer) const;
  void MerkleRootComputeTarget(std::span<const uint8_t> buffer) const;
  void StumpUpdateTarget(std::span<const uint8_t> buffer) const;
  void Bip32DeriveFromPathTarget(std::span<const uint8_t> buffer) const;
  void Musig2KeyAggTarget(std::span<const uint8_t> buffer) const;
  void Aes256CbcTarget(std::span<const uint8_t> buffer) const;
  void Musig2SignSessionTarget(std::span<const uint8_t> buffer) const;
  void SilentPaymentsCreateOutputsTarget(std::span<const uint8_t> buffer) const;
};
} // namespace bitcoinfuzz
