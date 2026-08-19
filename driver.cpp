#include <algorithm>
#include <cassert>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include <string_view>
#include <unistd.h>

#include "driver.h"
#include <bitcoinfuzz/basemodule.h>
#include <bitcoinfuzz/module_registry.h>
#include <bitcoinfuzz/util.h>

namespace bitcoinfuzz {
template <typename T>
void Driver::LogResponse(const std::string &module_name,
                         const T &response) const {
  if (!log_outputs)
    return;
  std::cout << "Module: " << module_name << std::endl;
  std::cout << "Result: " << response << std::endl;
}

template <typename T>
void Driver::VerifyMatchingResponse(std::optional<T> &last_response,
                                    std::string &last_module_name,
                                    const std::string &module_name,
                                    const T &response,
                                    std::string_view failure_message) const {
  if (last_response.has_value() && response != *last_response) {
    std::cout << failure_message << std::endl;
    std::cout << "Module: " << module_name << std::endl;
    std::cout << "Result: " << response << std::endl;
    std::cout << "Module: " << last_module_name << std::endl;
    std::cout << "Result: " << *last_response << std::endl;
    assert(false);
  }

  LogResponse(module_name, response);
  last_response = response;
  last_module_name = module_name;
}

void Driver::LoadModule(std::shared_ptr<BaseModule> module) {
  modules[module->name] = module;
  module_logger.addModule(module->name);
}

void Driver::ScriptTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;
  for (auto &module : modules) {
    std::optional<std::string> res{module.second->script_parse(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Script parse failed");
  }
}

void Driver::BlockDeserializationTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;
  for (auto &module : modules) {
    std::optional<std::string> res{module.second->deserialize_block(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Block deserialization failed");
  }
}

void Driver::ScriptEvalTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  std::vector<uint8_t> input_data = provider.ConsumeBytes<uint8_t>(
      provider.ConsumeIntegralInRange<size_t>(0, 1024));

  auto flags = provider.ConsumeIntegral<unsigned int>();

  std::optional<bool> last_response{std::nullopt};
  std::string last_module_name;
  for (auto &module : modules) {
#ifdef BTCD
    const bool has_btcd_unsupported_sigop =
        std::ranges::find(input_data, 0xAC) != input_data.end() ||
        std::ranges::find(input_data, 0xAE) != input_data.end() ||
        std::ranges::find(input_data, 0xAF) != input_data.end();
    if (module.first == "Btcd" && has_btcd_unsupported_sigop)
      continue;
#endif
#ifdef NBITCOIN
    const bool has_nbitcoin_unsupported_opcode =
        std::ranges::find(input_data, 0xB2) != input_data.end();
    if (module.first == "NBitcoin" && has_nbitcoin_unsupported_opcode)
      continue;
#endif
    std::optional<bool> res{
        module.second->script_eval(input_data, flags, /*version=*/0)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Script evaluation failed");
  }
}

void Driver::VerifyScriptTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  std::vector<uint8_t> script_sig = provider.ConsumeBytes<uint8_t>(
      provider.ConsumeIntegralInRange<size_t>(0, 1024));

  std::vector<uint8_t> script_pubkey = provider.ConsumeBytes<uint8_t>(
      provider.ConsumeIntegralInRange<size_t>(0, 1024));

  std::optional<bool> last_response{std::nullopt};
  std::string last_module_name;
  for (auto &module : modules) {
#if defined(BTCD) || defined(GOCOIN)
    // Skip these opcodes only for implementations that disagree with Core's
    // FindAndDelete handling, while continuing to compare all other modules.
    auto opcodes_to_skip = [](unsigned char op) {
      return op >= 0xAC && op <= 0xAF;
    };
    bool has_opcode_mismatch =
        std::ranges::any_of(script_sig, opcodes_to_skip) ||
        std::ranges::any_of(script_pubkey, opcodes_to_skip);
    if (has_opcode_mismatch &&
        (module.first == "Btcd" || module.first == "Gocoin"))
      continue;
#endif
    std::optional<bool> res{
        module.second->verify_script(script_sig, script_pubkey)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Script verification failed");
  }
}

void Driver::DescriptorParseTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  std::string desc{provider.ConsumeRemainingBytesAsString()};
  std::optional<bool> last_response{std::nullopt};
  std::string last_module_name;
  for (auto &module : modules) {
    std::optional<bool> res{module.second->descriptor_parse(desc)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Descriptor parse failed for " + desc);
  }
}

void Driver::MiniscriptParseTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  std::string miniscript{provider.ConsumeRemainingBytesAsString()};
  // Skip these cases
  if (strcmp(miniscript.c_str(), "1") == 0 ||
      strcmp(miniscript.c_str(), "0") == 0)
    return;
  std::optional<bool> last_response{std::nullopt};
  std::string last_module_name;
  for (auto &module : modules) {
    std::optional<bool> res{module.second->miniscript_parse(miniscript)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Miniscript parse failed for " + miniscript);
  }
}

void Driver::InvoiceDeserializationTarget(
    std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  std::string invoice{provider.ConsumeRemainingBytesAsString()};
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->deserialize_invoice(invoice)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Invoice deserialization failed for " + invoice);
  }
}

void Driver::AddressParseTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  std::string address{provider.ConsumeRemainingBytesAsString()};

  // Two independent comparison chains.
  //
  // Segwit addresses whose version and program size match none of the defined
  // output types -- witness versions 2..16, and version 1 programs that are not
  // 32 bytes -- land in the second chain, tagged "WITNESS_UNKNOWN:v<version>:
  // <program>". Whether to decode such an address at all is a policy call
  // rather than a consensus one (btcd refuses outright, Core hands back a
  // WitnessUnknown destination), so an accept-versus-reject split there is not
  // a bug and belongs in its own chain. What must still agree is the version
  // and program recovered by the modules that do accept -- which is precisely
  // the BIP-350 bech32m boundary, and which the previous blanket "UNK:" skip
  // dropped from the comparison entirely.
  //
  // "UNK:" is still skipped. It is what modules report when they cannot
  // classify a result at all, and it is not reached along a single shared code
  // path: libbitcoin also uses it for legacy addresses carrying a non-mainnet
  // version byte, which the mainnet-pinned modules reject as "INVALID".
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;
  std::optional<std::string> last_witness_unknown{std::nullopt};
  std::string last_witness_unknown_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->address_parse(address)};
    if (!res.has_value() || res->starts_with("UNK:"))
      continue;

    const bool witness_unknown{res->starts_with("WITNESS_UNKNOWN:")};
    std::optional<std::string> &last{witness_unknown ? last_witness_unknown
                                                     : last_response};
    std::string &last_name{witness_unknown ? last_witness_unknown_module_name
                                           : last_module_name};

    LogResponse(module.first, *res);

    if (last.has_value()) {
      if (*res != *last) {
        std::cout << "Input address: " << address << "\n";
        std::cout << "MISMATCH DETECTED between " << last_name << " and "
                  << module.first << "!"
                  << "\n";
        std::cout << "  " << last_name << ": " << *last << "\n";
        std::cout << "  " << module.first << ": " << *res << std::endl;
        assert(*res == *last);
      }
    }
    last = *res;
    last_name = module.first;
  }
}

void Driver::PSBTParseTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->psbt_parse(buffer)};
    if (!res.has_value())
      continue;

    // Treat malformed parses consistently across modules. For this target, an
    // empty result or a zero-input/zero-output transaction is not a meaningful
    // successful parse and should not participate in differential comparison.
    if (res->empty() || res->find("inputs=0") != std::string::npos ||
        res->find("outputs=0") != std::string::npos)
      continue;

    LogResponse(module.first, *res);

    if (last_response.has_value()) {
      if (*res != *last_response) {
        std::cout << "Input PSBT (truncated): ";
        for (size_t i = 0; i < std::min(size_t(32), buffer.size()); ++i)
          printf("%02x", buffer[i]);
        if (buffer.size() > 32)
          std::cout << "...";
        std::cout << " (" << buffer.size() << " bytes)\n";

        std::cout << "MISMATCH DETECTED between " << last_module_name << " and "
                  << module.first << "!"
                  << "\n";

        // Find and highlight the differences
        std::string last = *last_response;
        std::string current = *res;

        // Print the full outputs only if they're reasonably sized
        if (last.size() < 1000 && current.size() < 1000) {
          std::cout << "  " << last_module_name << ": " << last << "\n";
          std::cout << "  " << module.first << ": " << current << "\n";
        } else {
          // Find first differing position
          size_t pos = 0;
          while (pos < last.size() && pos < current.size() &&
                 last[pos] == current[pos])
            pos++;

          // Print context around the difference
          size_t context = 20;
          size_t start = (pos > context) ? pos - context : 0;

          std::cout << "  Difference at position " << pos << "\n";
          std::cout << "  " << last_module_name << " (excerpt): ..."
                    << last.substr(start, context * 2) << "...\n";
          std::cout << "  " << module.first << " (excerpt): ..."
                    << current.substr(start, context * 2) << "...\n";
        }
      }

      assert(*res == *last_response);
    }
    last_response = *res;
    last_module_name = module.first;
  }
}

void Driver::AddrV2Target(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;
  for (auto &module : modules) {
    std::optional<std::string> res{module.second->addrv2_parse(buffer)};
    if (!res.has_value())
      continue;

    LogResponse(module.first, *res);

    if (last_response.has_value()) {
      if (*res != *last_response) {
#ifdef BTCD
        // Skip mismatches involving btcd when i2p or cjdns addresses are
        // present (btcd always skips i2p and cjdns)
        bool involves_btcd =
            (module.first == "Btcd" || last_module_name == "Btcd");
        bool has_i2p_or_cjdns =
            (res->find("i2p") != std::string::npos ||
             res->find("cjdns") != std::string::npos ||
             last_response->find("i2p") != std::string::npos ||
             last_response->find("cjdns") != std::string::npos);
        if (involves_btcd && has_i2p_or_cjdns) {
          last_response = *res;
          last_module_name = module.first;
          continue;
        }
#endif
        std::cout << "Addrv2 parse failed" << std::endl;
        std::cout << "Module: " << module.first << std::endl;
        std::cout << "Result: " << *res << std::endl;
        std::cout << "Module: " << last_module_name << std::endl;
        std::cout << "Result: " << *last_response << std::endl;
      }
      assert(*res == *last_response);
    }
    last_response = *res;
    last_module_name = module.first;
  }
}

void Driver::OfferDeserializationTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  std::string offer{provider.ConsumeRemainingBytesAsString()};
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->deserialize_offer(offer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Offer deserialization failed for " + offer);
  }
}

void Driver::CompactBlocksTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->cmpctblocks_parse(buffer)};
    if (!res.has_value())
      continue;

    LogResponse(module.first, *res);
    const std::string comparable_response{res->starts_with("ERR:") ? "ERR"
                                                                   : *res};

    if (last_response.has_value()) {
      if (comparable_response != *last_response) {
        if (!buffer.empty()) {
          for (size_t i = 0; i < std::min(size_t(32), buffer.size()); ++i)
            printf("%02x", buffer[i]);
          if (buffer.size() > 32)
            std::cout << "...";
        }

        std::cout << " (" << buffer.size() << "bytes)\n";
        std::cout << "MISMATCH DETECTED between " << last_module_name << " and "
                  << module.first << "!"
                  << "\n";
        std::cout << "  " << last_module_name << ": " << *last_response << "\n";
        std::cout << "  " << module.first << ": " << comparable_response
                  << "\n";
      }

      assert(comparable_response == *last_response);
    }
    last_response = comparable_response;
    last_module_name = module.first;
  }
}

void Driver::ParseP2PMessageTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->parse_p2p_message(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "P2P message parsing failed");
  }
}

void Driver::TransactionEvalTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->transaction_eval(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Transaction evaluation failed");
  }
}

void Driver::KernelBlockTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->kernel_block(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(
        last_response, last_module_name, module.first, *res,
        "Block parsing from libbitcoinkernel binding failed:");
  }
}

void Driver::KernelTransactionTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->kernel_transaction(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(
        last_response, last_module_name, module.first, *res,
        "Transaction parsing from libbitcoinkernel binding failed:");
  }
}

void Driver::KernelBlockCheckTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->kernel_block_check(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(
        last_response, last_module_name, module.first, *res,
        "Block validation from libbitcoinkernel binding failed:");
  }
}

void Driver::ParseLightningP2pMessageTarget(
    std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->parse_p2p_lightning_message(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Lightning P2P message parsing failed");
  }
}
void Driver::Bip32MasterKeygenTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->bip32_master_keygen(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "BIP32 master keygen failed");
  }
}

void Driver::PrivateToPublicKeyTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  if (buffer.size() < 32)
    return;

  std::vector<uint8_t> privkey_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->private_to_public_key(privkey_buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "PrivateToPublicKey Target failed");
  }
}

void Driver::PubkeyParseTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

#ifdef RUST_K256
  // Known SEC1 encoding-policy splits, skipped for K256 only to keep the
  // differential meaningful: its sec1 layer has no hybrid tag (rejects
  // 0x06/0x07 where libsecp256k1 and decred's secp256k1 accept them) and
  // additionally accepts the compact point encoding (0x05) everyone else
  // rejects.
  const bool is_hybrid =
      buffer.size() == 65 && (buffer[0] == 0x06 || buffer[0] == 0x07);
  const bool is_compact = buffer.size() == 33 && buffer[0] == 0x05;
#endif

  for (auto &module : modules) {
#ifdef RUST_K256
    if (module.first == "K256" && (is_hybrid || is_compact))
      continue;
#endif
    std::optional<std::string> res{module.second->pubkey_parse(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Public key parse failed");
  }
}

void Driver::SignCompactTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  if (buffer.size() < 64)
    return;

  std::vector<uint8_t> privkey_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> hash_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->sign_compact(privkey_buffer, hash_buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "SignCompact Target failed");
  }
}

void Driver::SignDerTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  if (buffer.size() < 64)
    return;

  std::vector<uint8_t> privkey_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> hash_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->sign_der(privkey_buffer, hash_buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "SignDer Target failed");
  }
}

void Driver::SignVerifyTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  if (buffer.size() < 72)
    return;

  std::vector<uint8_t> privkey_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> hash_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> sign_buffer = provider.ConsumeRemainingBytes<uint8_t>();
  std::optional<bool> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<bool> res{
        module.second->sign_verify(privkey_buffer, hash_buffer, sign_buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "SignVerify Target failed");
  }
}

void Driver::ECDHTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  if (buffer.size() < 65)
    return;

  std::vector<uint8_t> privkey_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> pubkey_buffer = provider.ConsumeBytes<uint8_t>(33);
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->ecdh(privkey_buffer, pubkey_buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "ECDH Target failed");
  }
}

void Driver::SignSchnorrTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  if (buffer.size() < 96)
    return;

  std::vector<uint8_t> privkey_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> hash_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> aux_buffer = provider.ConsumeBytes<uint8_t>(32);
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->sign_schnorr(privkey_buffer, hash_buffer, aux_buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "SignSchnorr Target failed");
  }
}

void Driver::Bip32DeserializeExtendedKeyTarget(
    std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->bip32_deserialize_extended_key(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "BIP32 deserialize extended key failed");
  }
}

void Driver::DecodeEllswiftTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  if (buffer.size() != 64)
    return;

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->decode_ellswift(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "DecodeEllswiftTarget Target failed");
  }
}

void Driver::EllswiftRoundTripXTarget(std::span<const uint8_t> buffer) const {
  if (buffer.size() != 32)
    return;

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->roundtrip_ellswift(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "EllswiftRoundTripXTarget failed");
  }
}

void Driver::SchnorrVerifyTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  if (buffer.size() != 128)
    return;

  std::vector<uint8_t> privkey = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> hash = provider.ConsumeBytes<uint8_t>(32);
  std::vector<uint8_t> sign = provider.ConsumeBytes<uint8_t>(64);
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->schnorr_verify(privkey, hash, sign)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "SchnorrVerifyTarget failed");
  }
}

void Driver::DecodeOnionTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->decode_onion(buffer)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Onion decoding failed");
  }
}

void Driver::StumpModifyAddTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());

  std::vector<std::vector<uint8_t>> add_hashes;
  while (true) {
    auto hash = provider.ConsumeBytes<uint8_t>(32);
    if (hash.size() < 32) {
      break;
    }
    // Skip all-zero hashes because Utreexod's dynamic accumulator
    // implementation treats them as a special case (empty tree), but other
    // implementations may handle that differently.
    if (std::all_of(hash.begin(), hash.end(),
                    [](uint8_t byte) { return byte == 0; })) {
      continue;
    }
    add_hashes.push_back(std::move(hash));
  }

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->stump_modify_add(add_hashes)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "StumpModifyAddTarget failed");
  }
}

void Driver::MerkleRootComputeTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());

  std::vector<std::vector<uint8_t>> hashes;
  while (true) {
    auto hash = provider.ConsumeBytes<uint8_t>(32);
    if (hash.size() < 32) {
      break;
    }
    hashes.push_back(std::move(hash));
  }

  // Skip empty lists: the empty-tree result differs by design across
  // implementations (Bitcoin Core returns the zero hash, rust-bitcoin
  // returns None, gocoin's CalcMerkle would index out of range). An empty
  // transaction list is consensus-invalid anyway, so there is no
  // interesting differential to compare here.
  if (hashes.empty())
    return;

  // Each module response is either the sentinel "REJECTED" (the library
  // refuses to compute a root for this list, e.g. rust-bitcoin rejects
  // CVE-2012-2459-mutated lists) or "<root_hex>;mutated=<0|1>". Roots are
  // compared across all modules that produce one, while the mutation
  // *detection* is compared across every responding module: a module that
  // reports "mutated=1" and a module that answers "REJECTED" agree.
  std::optional<std::string> last_root{std::nullopt};
  std::string last_root_module;
  std::optional<bool> last_detected{std::nullopt};
  std::string last_detected_module;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->merkle_root_compute(hashes)};
    if (!res.has_value())
      continue;

    std::optional<std::string> root{std::nullopt};
    bool detected{false};
    if (*res == "REJECTED") {
      detected = true;
    } else {
      const auto sep{res->rfind(";mutated=")};
      // A non-sentinel response must carry the mutation flag; anything else
      // is a bug in the module wrapper itself.
      assert(sep != std::string::npos);
      const std::string flag{res->substr(sep + 9)};
      assert(flag == "0" || flag == "1");
      root = res->substr(0, sep);
      detected = flag == "1";
    }

    if (root.has_value()) {
      VerifyMatchingResponse(last_root, last_root_module, module.first, *root,
                             "Merkle root computation failed");
    }
    VerifyMatchingResponse(last_detected, last_detected_module, module.first,
                           detected, "Merkle mutation detection failed");
  }
}

void Driver::Bip32DeriveFromPathTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  std::string path{provider.ConsumeRemainingBytesAsString()};
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->bip32_derive_from_path(buffer)};
    if (!res.has_value())
      continue;
    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "BIP32 derive from path failed");
  }
}

void Driver::Musig2KeyAggTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());

  // Number of signers to aggregate (MuSig2 requires at least one key).
  size_t num_keys = provider.ConsumeIntegralInRange<size_t>(1, 100);

  // Concatenated 32-byte private keys, one per signer. Each module derives the
  // corresponding public key and aggregates. Feeding scalars (rather than raw
  // pubkeys) keeps ~100% of inputs valid, so the fuzzer spends its budget in
  // the BIP-327 aggregation logic instead of failing pubkey parsing.
  std::vector<uint8_t> seckeys = provider.ConsumeBytes<uint8_t>(num_keys * 32);
  if (seckeys.size() != num_keys * 32)
    return; // Not enough data for the requested number of keys.

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    // nullopt: an input scalar was invalid (rare, symmetric) -> skip.
    // "AGG_FAIL": aggregation itself was rejected -> compared, so an
    // accept-vs-reject disagreement between modules trips the assert below.
    std::optional<std::string> res{module.second->musig2_key_agg(seckeys)};
    if (!res.has_value())
      continue;
    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "MuSig2 Key Aggregation failed");
  }
}

void Driver::Musig2SignSessionTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  const size_t num_keys = provider.ConsumeIntegralInRange<size_t>(1, 6);

  Musig2SignSessionInput input;
  input.seckeys = provider.ConsumeBytes<uint8_t>(num_keys * 32);
  input.msg32 = provider.ConsumeBytes<uint8_t>(32);
  input.nonce_seeds = provider.ConsumeBytes<uint8_t>(num_keys * 32);
  if (input.seckeys.size() != num_keys * 32 || input.msg32.size() != 32 ||
      input.nonce_seeds.size() != num_keys * 32) {
    return;
  }

  input.use_extra_input = provider.ConsumeBool();
  if (input.use_extra_input) {
    input.extra_input = provider.ConsumeBytes<uint8_t>(32);
    if (input.extra_input.size() != 32)
      return;
  }

  // Chained tweaks in fuzzer-chosen type and order.
  const size_t num_tweaks = provider.ConsumeIntegralInRange<size_t>(0, 4);
  for (size_t i = 0; i < num_tweaks; ++i) {
    Musig2Tweak tweak;
    tweak.is_xonly = provider.ConsumeBool();
    const std::vector<uint8_t> tweak_bytes = provider.ConsumeBytes<uint8_t>(32);
    if (tweak_bytes.size() != 32)
      return;
    std::copy(tweak_bytes.begin(), tweak_bytes.end(), tweak.tweak.begin());
    input.tweaks.push_back(tweak);
  }

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->musig2_sign_session(input)};
    if (!res.has_value())
      continue;
    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "MuSig2 signing session failed");
  }
}

void Driver::Aes256CbcTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());
  // key(32) + iv(16) + pad flag(1) + at least one data byte. Empty data is
  // excluded because Bitcoin Core's CBC routines reject it while other
  // implementations accept it, which is not an interesting difference.
  if (buffer.size() < 50)
    return;

  std::vector<uint8_t> key = ConsumeFixedLengthByteVector(provider, 32);
  std::vector<uint8_t> iv = ConsumeFixedLengthByteVector(provider, 16);
  const bool pad = provider.ConsumeBool();
  std::vector<uint8_t> data = provider.ConsumeRemainingBytes<uint8_t>();
  if (data.empty())
    return;

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->aes256_cbc(key, iv, pad, data)};
    if (!res.has_value())
      continue;

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "AES256-CBC Target failed");
  }
}

void Driver::SilentPaymentsCreateOutputsTarget(
    std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());

  // BIP-352 requires at least one eligible input and one recipient. The upper
  // bounds keep a single execution cheap; the recipient group limit (2323) is
  // far out of reach for a fuzzer anyway.
  const size_t num_inputs = provider.ConsumeIntegralInRange<size_t>(1, 8);
  const size_t num_recipients = provider.ConsumeIntegralInRange<size_t>(1, 8);
  // Recipients draw their scan key from a smaller pool so that several of them
  // share one scan key. Sharing is what makes a recipient "group" in BIP-352,
  // and groups are where the k counter is incremented per output.
  const size_t num_scan_keys =
      provider.ConsumeIntegralInRange<size_t>(1, num_recipients);
  // Labels come from a small pool rather than one per recipient: support is
  // thin and inconsistent across implementations, and the interesting shapes
  // are a label reused by several recipients and a labeled address sharing a
  // group with an unlabeled one. An empty pool leaves every recipient
  // unlabeled, which keeps the modules that have no label API in the
  // comparison for those inputs.
  const size_t num_labels = provider.ConsumeIntegralInRange<size_t>(0, 3);

  SilentPaymentsCreateOutputsInput input;

  const std::vector<uint8_t> outpoint = provider.ConsumeBytes<uint8_t>(36);
  if (outpoint.size() != 36)
    return;
  std::copy(outpoint.begin(), outpoint.end(), input.outpoint_smallest.begin());

  input.input_seckeys = provider.ConsumeBytes<uint8_t>(num_inputs * 32);
  if (input.input_seckeys.size() != num_inputs * 32)
    return;
  for (size_t i = 0; i < num_inputs; ++i) {
    input.input_is_taproot.push_back(provider.ConsumeBool() ? 1 : 0);
  }

  const std::vector<uint8_t> scan_key_pool =
      provider.ConsumeBytes<uint8_t>(num_scan_keys * 32);
  if (scan_key_pool.size() != num_scan_keys * 32)
    return;

  std::vector<uint32_t> label_pool;
  label_pool.reserve(num_labels);
  for (size_t i = 0; i < num_labels; ++i) {
    label_pool.push_back(provider.ConsumeIntegral<uint32_t>());
  }

  input.scan_seckeys.reserve(num_recipients * 32);
  input.spend_seckeys = provider.ConsumeBytes<uint8_t>(num_recipients * 32);
  if (input.spend_seckeys.size() != num_recipients * 32)
    return;
  for (size_t i = 0; i < num_recipients; ++i) {
    const size_t scan_key_index =
        provider.ConsumeIntegralInRange<size_t>(0, num_scan_keys - 1);
    const auto begin = scan_key_pool.begin() + (scan_key_index * 32);
    input.scan_seckeys.insert(input.scan_seckeys.end(), begin, begin + 32);

    const bool is_labeled = !label_pool.empty() && provider.ConsumeBool();
    input.recipient_is_labeled.push_back(is_labeled ? 1 : 0);
    input.recipient_labels.push_back(
        is_labeled ? label_pool[provider.ConsumeIntegralInRange<size_t>(
                         0, num_labels - 1)]
                   : 0);
  }

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    // Rejections are reported as sentinels ("INVALID_SECKEY", "CREATE_FAIL")
    // rather than as nullopt, so they are compared like any other response and
    // an accept-vs-reject disagreement between modules trips the assert.
    // nullopt is left for modules that do not implement the target at all.
    std::optional<std::string> res{
        module.second->silentpayments_create_outputs(input)};
    if (!res.has_value())
      continue;
    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "Silent Payments output creation failed");
  }
}

namespace {
// Number of 5-bit groups in the data part of a segwit address: one group for
// the witness version, plus the zero-padded regrouping of the program.
size_t Bech32DataLength(size_t program_len) {
  return 1 + (program_len * 8 + 4) / 5;
}

std::string HexString(std::span<const uint8_t> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const uint8_t b : bytes) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 0x0f]);
  }
  return out;
}
} // namespace

void Driver::Bech32RoundtripTarget(std::span<const uint8_t> buffer) const {
  FuzzedDataProvider provider(buffer.data(), buffer.size());

  // A quarter of the inputs drive the bare 5<->8 bit regrouping primitive; the
  // rest drive the full segwit address round-trip.
  if (provider.ConsumeIntegralInRange<uint8_t>(0, 3) == 0) {
    Bech32ConvertBitsInput input;
    // 5->8 is the decode direction (unpacking base32 groups into bytes), 8->5
    // the encode direction.
    const bool unpack{provider.ConsumeBool()};
    input.from_bits = unpack ? 5 : 8;
    input.to_bits = unpack ? 8 : 5;
    input.pad = provider.ConsumeBool();
    // Unmasked data lets 5-bit groups carry values above 31, which no bech32
    // string can produce but which callers of these public helpers can pass in.
    // An implementation has to reject those; one that truncates them instead
    // maps two distinct inputs onto one output. Masked is the default so the
    // budget is not spent entirely on the out-of-range case.
    const bool mask{!provider.ConsumeBool()};
    input.data = provider.ConsumeRemainingBytes<uint8_t>();
    if (mask && input.from_bits == 5) {
      for (uint8_t &b : input.data)
        b &= 0x1f;
    }

    std::optional<std::string> last_response{std::nullopt};
    std::string last_module_name;

    for (auto &module : modules) {
      std::optional<std::string> res{module.second->bech32_convert_bits(input)};
      if (!res.has_value())
        continue;

      LogResponse(module.first, *res);

      if (last_response.has_value() && *res != *last_response) {
        std::cout << "Input convert bits: " << static_cast<int>(input.from_bits)
                  << "->" << static_cast<int>(input.to_bits)
                  << " pad=" << (input.pad ? "1" : "0")
                  << " data=" << HexString(input.data) << "\n";
        std::cout << "MISMATCH DETECTED between " << last_module_name << " and "
                  << module.first << "!" << "\n";
        std::cout << "  " << last_module_name << ": " << *last_response << "\n";
        std::cout << "  " << module.first << ": " << *res << std::endl;
        assert(*res == *last_response);
      }
      last_response = *res;
      last_module_name = module.first;
    }
    return;
  }

  Bech32SegwitInput input;
  input.witver = provider.ConsumeIntegralInRange<uint8_t>(0, 16);
  // BIP-141 fixes the version 0 program at 20 or 32 bytes. Generating only
  // those keeps version 0 inputs valid instead of burning the budget on a
  // length check every implementation performs before touching the checksum.
  const size_t program_len{
      input.witver == 0 ? (provider.ConsumeBool() ? 20u : 32u)
                        : provider.ConsumeIntegralInRange<size_t>(2, 40)};
  const size_t hrp_len{provider.ConsumeIntegralInRange<size_t>(1, 83)};

  input.program = ConsumeFixedLengthByteVector(provider, program_len);
  input.hrp.reserve(hrp_len);
  for (size_t i = 0; i < hrp_len; ++i) {
    // BIP-173 allows any US-ASCII character in [33,126] in the HRP. Uppercase
    // is folded rather than rejected: an uppercase HRP makes the encoding
    // invalid by definition and asserts inside some encoders, so it would only
    // ever produce noise.
    uint8_t c{provider.ConsumeIntegralInRange<uint8_t>(33, 126)};
    if (c >= 'A' && c <= 'Z')
      c += 'a' - 'A';
    input.hrp.push_back(static_cast<char>(c));
  }

  // BIP-173 caps a segwit address at 90 characters. Over-cap inputs are still
  // handed to every module -- an over-long HRP is exactly what walks an encoder
  // off the end of a fixed-size output buffer -- but their responses are not
  // compared: implementations legitimately split between refusing to encode and
  // emitting a string their own decoder then rejects, and that split would bury
  // the checksum divergences this target is looking for.
  const size_t encoded_len{input.hrp.size() + 1 +
                           Bech32DataLength(program_len) + 6};
  const bool compare{encoded_len <= 90};

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{
        module.second->bech32_segwit_roundtrip(input)};
    if (!res.has_value())
      continue;

    LogResponse(module.first, *res);
    if (!compare)
      continue;

    if (last_response.has_value() && *res != *last_response) {
      std::cout << "Input hrp: " << input.hrp << "\n";
      std::cout << "Input witness version: " << static_cast<int>(input.witver)
                << "\n";
      std::cout << "Input witness program: " << HexString(input.program)
                << "\n";
      std::cout << "MISMATCH DETECTED between " << last_module_name << " and "
                << module.first << "!" << "\n";
      std::cout << "  " << last_module_name << ": " << *last_response << "\n";
      std::cout << "  " << module.first << ": " << *res << std::endl;
      assert(*res == *last_response);
    }
    last_response = *res;
    last_module_name = module.first;
  }
}

void Driver::Run(const uint8_t *data, const size_t size,
                 const std::string &target) const {
  std::span<const uint8_t> buffer{data, size};
  if (target == "script") {
    this->ScriptTarget(buffer);
  } else if (target == "deserialize_block") {
    this->BlockDeserializationTarget(buffer);
  } else if (target == "script_eval") {
    this->ScriptEvalTarget(buffer);
  } else if (target == "verify_script") {
    this->VerifyScriptTarget(buffer);
  } else if (target == "descriptor_parse") {
    this->DescriptorParseTarget(buffer);
  } else if (target == "miniscript_parse") {
    this->MiniscriptParseTarget(buffer);
  } else if (target == "deserialize_invoice") {
    this->InvoiceDeserializationTarget(buffer);
  } else if (target == "address_parse") {
    this->AddressParseTarget(buffer);
  } else if (target == "psbt_parse") {
    this->PSBTParseTarget(buffer);
  } else if (target == "addrv2") {
    this->AddrV2Target(buffer);
  } else if (target == "deserialize_offer") {
    this->OfferDeserializationTarget(buffer);
  } else if (target == "cmpctblocks_parse") {
    this->CompactBlocksTarget(buffer);
  } else if (target == "parse_p2p_message") {
    this->ParseP2PMessageTarget(buffer);
  } else if (target == "parse_p2p_lightning_message") {
    this->ParseLightningP2pMessageTarget(buffer);
  } else if (target == "transaction_eval") {
    this->TransactionEvalTarget(buffer);
  } else if (target == "bip32_master_keygen") {
    this->Bip32MasterKeygenTarget(buffer);
  } else if (target == "kernel_block") {
    this->KernelBlockTarget(buffer);
  } else if (target == "kernel_transaction") {
    this->KernelTransactionTarget(buffer);
  } else if (target == "kernel_block_check") {
    this->KernelBlockCheckTarget(buffer);
  } else if (target == "private_to_public_key") {
    this->PrivateToPublicKeyTarget(buffer);
  } else if (target == "pubkey_parse") {
    this->PubkeyParseTarget(buffer);
  } else if (target == "sign_compact") {
    this->SignCompactTarget(buffer);
  } else if (target == "sign_der") {
    this->SignDerTarget(buffer);
  } else if (target == "sign_verify") {
    this->SignVerifyTarget(buffer);
  } else if (target == "ecdh") {
    this->ECDHTarget(buffer);
  } else if (target == "sign_schnorr") {
    this->SignSchnorrTarget(buffer);
  } else if (target == "bip32_deserialize_extended_key") {
    this->Bip32DeserializeExtendedKeyTarget(buffer);
  } else if (target == "decode_ellswift") {
    this->DecodeEllswiftTarget(buffer);
  } else if (target == "roundtrip_ellswift") {
    this->EllswiftRoundTripXTarget(buffer);
  } else if (target == "schnorr_verify") {
    this->SchnorrVerifyTarget(buffer);
  } else if (target == "decode_onion") {
    this->DecodeOnionTarget(buffer);
  } else if (target == "stump_modify_add") {
    this->StumpModifyAddTarget(buffer);
  } else if (target == "merkle_root_compute") {
    this->MerkleRootComputeTarget(buffer);
  } else if (target == "bip32_derive_from_path") {
    this->Bip32DeriveFromPathTarget(buffer);
  } else if (target == "musig2_key_agg") {
    this->Musig2KeyAggTarget(buffer);
  } else if (target == "aes256_cbc") {
    this->Aes256CbcTarget(buffer);
  } else if (target == "musig2_sign_session") {
    this->Musig2SignSessionTarget(buffer);
  } else if (target == "silentpayments_create_outputs") {
    this->SilentPaymentsCreateOutputsTarget(buffer);
  } else if (target == "bech32_roundtrip") {
    this->Bech32RoundtripTarget(buffer);
  } else {
    std::cout << "Unknown target: " << target << std::endl;
    assert(false);
  }
};

} // namespace bitcoinfuzz
