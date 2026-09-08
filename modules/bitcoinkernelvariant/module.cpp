#include "module.h"
#include "bitcoinkernel_variant_symbol_prefix.h"

#include <hash.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <ranges>
#include <span>
#include <sstream>
#include <string>

namespace {
std::string bytes_to_hex(std::span<const std::byte> bytes) {
  std::stringstream string_stream;
  string_stream << std::hex;
  for (const auto byte : bytes) {
    string_stream << std::setw(2) << std::setfill('0')
                  << std::to_integer<int>(byte);
  }

  return string_stream.str();
}

std::string hash_bytes_to_hex(std::span<const std::byte> bytes) {
  std::stringstream string_stream;
  string_stream << std::hex;
  for (const auto byte : bytes | std::views::reverse) {
    string_stream << std::setw(2) << std::setfill('0')
                  << std::to_integer<int>(byte);
  }

  return string_stream.str();
}

btck::ChainType decode_chain_type(uint8_t value) {
  constexpr std::array chain_types{
      btck::ChainType::MAINNET, btck::ChainType::TESTNET,
      btck::ChainType::TESTNET_4, btck::ChainType::SIGNET,
      btck::ChainType::REGTEST};
  return chain_types[value % chain_types.size()];
}

std::string chain_type_to_string(btck::ChainType chain_type) {
  switch (chain_type) {
  case btck::ChainType::MAINNET:
    return "mainnet";
  case btck::ChainType::TESTNET:
    return "testnet";
  case btck::ChainType::TESTNET_4:
    return "testnet4";
  case btck::ChainType::SIGNET:
    return "signet";
  case btck::ChainType::REGTEST:
    return "regtest";
  }

  assert(false);
}

btck::BlockCheckFlags decode_block_check_flags(uint8_t value) {
  auto flags = btck::BlockCheckFlags::BASE;
  if ((value & 0x01) != 0)
    flags |= btck::BlockCheckFlags::POW;
  if ((value & 0x02) != 0)
    flags |= btck::BlockCheckFlags::MERKLE;
  return flags;
}

char *libbitcoinkernel_transaction(std::span<const uint8_t> buffer) {
  try {
    const auto raw_span = std::as_bytes(buffer);
    btck::Transaction transaction{raw_span};

    const auto txid_bytes = transaction.Txid().ToBytes();
    std::string result = "txid=";
    result.append(hash_bytes_to_hex(txid_bytes));
    result.append(";");

    const auto txins = transaction.Inputs();
    for (const auto &txin : txins) {
      const auto outpoint = txin.OutPoint();
      uint32_t outpoint_index = outpoint.index();
      const auto outpoint_txid_bytes = outpoint.Txid().ToBytes();
      result.append("index=");
      result.append(std::to_string(outpoint_index));
      result.append("txid=");
      result.append(hash_bytes_to_hex(outpoint_txid_bytes));
      result.append(";");
    }

    const auto txouts = transaction.Outputs();
    for (const auto &txout : txouts) {
      int64_t txout_amount = txout.Amount();
      const auto script_pubkey_bytes = txout.GetScriptPubkey().ToBytes();
      result.append("amount=");
      result.append(std::to_string(txout_amount));
      result.append("script_pubkey=");
      result.append(bytes_to_hex(script_pubkey_bytes));
      result.append(";");
    }
    return strdup(result.c_str());
  } catch (...) {
    return strdup("0");
  }
}

char *libbitcoinkernel_block(std::span<const uint8_t> buffer) {
  try {
    const auto raw_span = std::as_bytes(buffer);
    btck::Block block{raw_span};

    const auto block_hash_bytes = block.GetHash().ToBytes();
    std::string result = hash_bytes_to_hex(block_hash_bytes);

    const auto txs = block.Transactions();
    for (const auto &tx : txs) {
      const auto txid_bytes = tx.Txid().ToBytes();
      result.append("txid=");
      result.append(hash_bytes_to_hex(txid_bytes));
      result.push_back(';');
    }
    return strdup(result.c_str());

  } catch (...) {
    return strdup("0");
  }
}

char *libbitcoinkernel_block_check(std::span<const uint8_t> buffer) {
  const uint8_t chain_selector = buffer.size() > 0 ? buffer[0] : 0;
  const uint8_t flag_selector = buffer.size() > 1 ? buffer[1] : 0;
  const auto chain_type = decode_chain_type(chain_selector);
  const auto flags = decode_block_check_flags(flag_selector);
  const auto raw_block = buffer.subspan(
      buffer.size() > 2 ? static_cast<size_t>(2) : buffer.size());

  std::string result = "chain=";
  result.append(chain_type_to_string(chain_type));
  result.append(";flags=");
  result.append(std::to_string(flag_selector & 0x03));
  result.push_back(';');

  try {
    btck::ChainParams chain_params{chain_type};
    const auto raw_span = std::as_bytes(raw_block);
    btck::Block block{raw_span};
    btck::BlockValidationState state{};
    const bool ok =
        block.Check(chain_params.GetConsensusParams(), flags, state);

    result.append("ok=");
    result.append(ok ? "1" : "0");
    result.append(";mode=");
    result.append(std::to_string(static_cast<int>(state.GetValidationMode())));
    result.append(";result=");
    result.append(
        std::to_string(static_cast<int>(state.GetBlockValidationResult())));
    result.append(";hash=");
    const auto block_hash_bytes = block.GetHash().ToBytes();
    result.append(hash_bytes_to_hex(block_hash_bytes));
    result.append(";txs=");
    result.append(std::to_string(block.CountTransactions()));
    result.push_back(';');
    return strdup(result.c_str());
  } catch (...) {
    result.append("err=exception;");
    return strdup(result.c_str());
  }
}

char *libbitcoinkernel_transaction_eval(std::span<const uint8_t> buffer) {
  try {
    const auto raw_span = std::as_bytes(buffer);
    btck::Transaction transaction{raw_span};
    btck::TxValidationState state{};
    if (!btck::CheckTransaction(transaction, state))
      return strdup("0");

    // Since bitcoinkernel does not provide a public interface for getting the
    // witness hash, we calculate it manually using core's internal API.
    // TODO: Swap wtxid calculation for kernel's getter when it becomes
    // available.
    //
    // Check if the transaction has witness data to avoid unnecessary
    // hashing in the case of non-witness-transactions.
    bool has_witness{false};
    for (const auto &input : transaction.Inputs()) {
      if (input.GetWitnessStack().CountItems() != 0) {
        has_witness = true;
        break;
      }
    }

    // ToBytes() serializes the transaction using TX_WITH_WITNESS
    // serialization-parameter object, so we can hash the serialized bytes.
    const auto transaction_bytes = transaction.ToBytes();
    std::array<unsigned char, CHash256::OUTPUT_SIZE> witness_hash{};
    if (!has_witness) {
      const auto txid = transaction.Txid().ToBytes();
      std::memcpy(witness_hash.data(), txid.data(), txid.size());
    } else {
      const std::span<const unsigned char> hash_input{
          reinterpret_cast<const unsigned char *>(transaction_bytes.data()),
          transaction_bytes.size()};
      CHash256{}.Write(hash_input).Finalize(witness_hash);
    }

    std::string result =
        hash_bytes_to_hex(std::as_bytes(std::span{witness_hash}));
    result += std::to_string(transaction_bytes.size());
    return strdup(result.c_str());
  } catch (...) {
    return strdup("0");
  }
}
} // namespace

namespace bitcoinfuzz {
namespace module {
BitcoinKernelVariant::BitcoinKernelVariant(void)
    : BaseModule("BitcoinKernelVariant") {}

std::optional<std::string> BitcoinKernelVariant::kernel_transaction(
    std::span<const uint8_t> buffer) const {
  auto result_ptr = libbitcoinkernel_transaction(buffer);
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free(result_ptr);
  return result;
}

std::optional<std::string>
BitcoinKernelVariant::kernel_block(std::span<const uint8_t> buffer) const {
  auto result_ptr = libbitcoinkernel_block(buffer);
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free(result_ptr);
  return result;
}

std::optional<std::string> BitcoinKernelVariant::kernel_block_check(
    std::span<const uint8_t> buffer) const {
  auto result_ptr = libbitcoinkernel_block_check(buffer);
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free(result_ptr);
  return result;
}

std::optional<std::string>
BitcoinKernelVariant::transaction_eval(std::span<const uint8_t> buffer) const {
  auto result_ptr = libbitcoinkernel_transaction_eval(buffer);
  if (result_ptr == nullptr)
    return std::nullopt;

  std::string result(result_ptr);
  free(result_ptr);
  return result;
}

} // namespace module
} // namespace bitcoinfuzz
