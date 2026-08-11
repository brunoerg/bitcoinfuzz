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

  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->address_parse(address)};
    if (!res.has_value() || res->starts_with("UNK:"))
      continue;

    LogResponse(module.first, *res);

    if (last_response.has_value()) {
      if (*res != *last_response) {
        std::cout << "Input address: " << address << "\n";
        std::cout << "MISMATCH DETECTED between " << last_module_name << " and "
                  << module.first << "!"
                  << "\n";
        std::cout << "  " << last_module_name << ": " << *last_response << "\n";
        std::cout << "  " << module.first << ": " << *res << "\n";
        assert(*res == *last_response);
      }
    }
    last_response = *res;
    last_module_name = module.first;
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
    if (res->empty() || res->find("in=0") != std::string::npos ||
        res->find("out=0") != std::string::npos)
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

void Driver::Musig2KeyAggCtxTarget(std::span<const uint8_t> buffer) const {
  std::optional<std::string> last_response{std::nullopt};
  std::string last_module_name;

  for (auto &module : modules) {
    std::optional<std::string> res{module.second->musig2_keyagg_ctx(buffer)};
    if (!res.has_value())
      continue;

    // A roundtrip failure is a library invariant violation, not a value to
    // compare: fail hard even when a single module implements this target.
    if (res->starts_with("ROUNDTRIP_FAIL")) {
      std::cout << "KeyAggContext roundtrip failure" << std::endl;
      std::cout << "Module: " << module.first << std::endl;
      std::cout << "Result: " << *res << std::endl;
      assert(false);
    }

    VerifyMatchingResponse(last_response, last_module_name, module.first, *res,
                           "MuSig2 KeyAggContext deserialization failed");
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
  } else if (target == "bip32_derive_from_path") {
    this->Bip32DeriveFromPathTarget(buffer);
  } else if (target == "musig2_key_agg") {
    this->Musig2KeyAggTarget(buffer);
  } else if (target == "aes256_cbc") {
    this->Aes256CbcTarget(buffer);
  } else if (target == "musig2_sign_session") {
    this->Musig2SignSessionTarget(buffer);
  } else if (target == "musig2_keyagg_ctx") {
    this->Musig2KeyAggCtxTarget(buffer);
  } else {
    std::cout << "Unknown target: " << target << std::endl;
    assert(false);
  }
};

} // namespace bitcoinfuzz
