#include <iomanip>
#include <optional>
#include <sstream>
#include <string>

#include "module.h"
#include <bitcoin/system.hpp>
#include <bitcoin/system/chain/enums/magic_numbers.hpp>
#include <bitcoin/system/machine/interpreter.hpp>

using namespace libbitcoin::system;

namespace {
class mock_signature_checker
    : public libbitcoin::system::machine::script_checker {
public:
  bool override_ecdsa_checksig_verify() const NOEXCEPT override { return true; }

  bool verify_schnorr_signature(
      const data_chunk &x_point, const hash_digest &hash,
      const ec_signature &signature) const NOEXCEPT override {
    return true;
  }

  error::op_error_t
  verify_locktime(bool input_final, uint64_t stack_locktime,
                  uint32_t transaction_locktime) const NOEXCEPT override {
    return error::op_success;
  }

  error::op_error_t verify_sequence(uint32_t transaction_version,
                                    uint32_t stack_sequence,
                                    uint32_t input_sequence) const NOEXCEPT {
    return error::op_success;
  }

  ~mock_signature_checker() override = default;
};
} // namespace

namespace bitcoinfuzz {
namespace module {

LibbitcoinSystem::LibbitcoinSystem(void) : BaseModule("LibbitcoinSystem") {}

std::optional<std::string>
LibbitcoinSystem::script_parse(std::span<const uint8_t> buffer) const {
  data_chunk data(buffer.begin(), buffer.end());

  // Prefix set to true treats the first byte as length
  // to match core's CScript deserialization
  chain::script script{data, true};

  if (!script.is_valid())
    return "0";

  // Match Bitcoin Core's IsUnspendable(), which checks for OP_RETURN prefix or
  // oversize script. Libbitcoin's script::is_unspendable() is a separate,
  // broader unspendability predicate, not the parser's short-circuit logic: it
  // classifies scripts whose first opcode is reserved or invalid as provably
  // unspendable. The reserved set includes OP_RETURN, but also other opcodes
  // that fail when reached as the first executed opcode, so using it here would
  // reject more scripts than Core's IsUnspendable().
  const auto &ops = script.ops();
  if ((!ops.empty() && ops.front() == chain::opcode::op_return) ||
      script.is_oversized())
    return "0";

  std::string result = std::to_string(script.signature_operations(false));

  bool is_witness = chain::script::is_witness_program_pattern(ops);
  result += is_witness ? "1" : "0";
  result += chain::script::is_relaxed_push_pattern(ops) ? "1" : "0";

  return result;
}

std::optional<std::string>
LibbitcoinSystem::transaction_eval(std::span<const uint8_t> buffer) const {
  data_chunk data(buffer.begin(), buffer.end());
  chain::transaction tx{data, true};
  static constexpr uint64_t max_money =
      21'000'000ULL * chain::satoshi_per_bitcoin;
  uint64_t total = 0;
  // is_valid() only signals deserialization succeeded — it accepts
  // 0-input/0-output and other consensus-invalid forms that bitcoin core's
  // CheckTransaction rejects. Use check() for libbitcoin-system's
  // context-free transaction checks. Some Core CheckTransaction rules, such as
  // duplicate inputs and output sum overflow, are placed differently in
  // libbitcoin: they are DoS guards or block-level redundancy checks rather
  // than part of transaction::check(). They are applied here explicitly so this
  // standalone transaction target matches Core's acceptance
  // surface.
  if (!tx.is_valid() || tx.check()) {
    return "0";
  }

  // Check for double spend, CVE-2018-17144. Libbitcoin checks for double spend
  // during block validation at block::is_internal_double_spend() called from
  // block::check().
  chain::points points;
  const auto inputs_ptr = tx.inputs_ptr();
  for (const auto &input_ptr : *inputs_ptr) {
    points.push_back(input_ptr->point());
  }
  if (!is_distinct(points))
    return "0";

  // Check for spend overflow, CVE-2010-5139. Libbitcoin checks for
  // overspending at block::is_overspent() called from block::accept()
  const auto outputs_ptr = tx.outputs_ptr();
  for (const auto &output : *outputs_ptr) {
    const uint64_t value = output->value();
    if (value > max_money)
      return "0";
    // Avoid overflow in the total sum
    if (total > max_money - value)
      return "0";
    total += value;
  }

  const std::string hash = encode_hash(tx.hash(true));
  const size_t size = tx.serialized_size(true);

  return hash + std::to_string(size);
}

std::optional<std::string>
LibbitcoinSystem::deserialize_block(std::span<const uint8_t> buffer) const {
  data_chunk data(buffer.begin(), buffer.end());
  chain::block_view blk_view{std::move(data), true};

  if (!blk_view.is_valid())
    return std::nullopt;

  // Checks if block is malleated or merkleroot is invalid.
  if (blk_view.identify())
    return "0";

  // Checks witness-commitment under BIP141
  chain::context ctx{};
  ctx.flags = chain::flags::bip141_rule;
  if (blk_view.identify(ctx))
    return "0";

  // Full object reconstruction after identity checks passed.
  const data_slice blk_data{buffer.data(), buffer.data() + buffer.size()};
  chain::block blk{blk_data, true};

  if (!blk.is_valid())
    return std::nullopt;

  // Attach hashes already computed by block_view so block checks do not
  // recompute them through transaction/header serialization.
  blk.header_ptr()->set_hash(blk_view.hash());

  const auto &tx_views = blk_view.views();
  const auto &txs = blk.transactions_ptr();
  for (size_t i = 0; i < txs->size(); ++i) {
    const auto &tx = (*txs)[i];

    tx->set_nominal_hash(tx_views[i].hash(true));

    if (tx->is_segregated())
      tx->set_witness_hash(tx_views[i].hash(true));
  }

  // Run full block check, skiping identity
  // checks already performed by block_view.
  if (blk.check(false))
    return "0";

  return encode_hash(blk_view.hash());
}

std::optional<std::string>
LibbitcoinSystem::address_parse(std::string str) const {
  try {
    std::string prefix;

    wallet::payment_address legacy_addr(str);
    if (legacy_addr) {
      switch (legacy_addr.prefix()) {
      case wallet::payment_address::mainnet_p2kh:
        prefix = "PKH:";
        break;
      case wallet::payment_address::mainnet_p2sh:
        prefix = "SH:";
        break;
      default:
        prefix = "UNK:";
      }
      return prefix + legacy_addr.encoded();
    }

    wallet::witness_address segwit_addr(str, false);
    if (segwit_addr &&
        segwit_addr.prefix() == wallet::witness_address::mainnet) {
      switch (segwit_addr.identifier()) {
      case wallet::witness_address::program_type::version0_p2kh:
        prefix = "WPKH:";
        break;
      case wallet::witness_address::program_type::version0_p2sh:
        prefix = "WSH:";
        break;
      case wallet::witness_address::program_type::version1_taproot:
        prefix = "TR:";
        break;
      case wallet::witness_address::program_type::unknown: {
        // A witness program with no defined output type yet: versions 2..16,
        // and version 1 programs that are not taproot. Reported with the
        // decoded version and program rather than as an opaque "UNK:" so the
        // driver can still compare what was decoded against the other
        // implementations that accept these addresses.
        std::ostringstream program;
        program << std::hex << std::setfill('0');
        for (const uint8_t byte : segwit_addr.program())
          program << std::setw(2) << static_cast<unsigned int>(byte);
        return "WITNESS_UNKNOWN:v" +
               std::to_string(
                   static_cast<unsigned int>(segwit_addr.version())) +
               ":" + program.str();
      }
      default:
        return "INVALID";
      }
      return prefix + segwit_addr.encoded();
    }
    return "INVALID";
  } catch (const std::exception &) {
    return "INVALID";
  }
}

std::optional<std::string>
LibbitcoinSystem::bip32_master_keygen(std::span<const uint8_t> buffer) const {

  data_chunk seed(buffer.begin(), buffer.end());
  wallet::hd_private master(seed, wallet::hd_private::mainnet);
  if (!master) {
    return "INVALID";
  }

  return master.encoded();
}

std::optional<std::string> LibbitcoinSystem::bip32_deserialize_extended_key(
    std::span<const uint8_t> buffer) const {
  try {
    if (buffer.empty()) {
      return "INVALID";
    }
    const std::string ext_str(reinterpret_cast<const char *>(buffer.data()),
                              buffer.size());

    const bool is_testnet = ext_str[0] == 't';

    auto format_key = [](const wallet::hd_lineage &lineage,
                         const wallet::hd_chain_code &chain,
                         const data_chunk &key_bytes) -> std::string {
      std::ostringstream ss;
      ss << std::hex << std::setfill('0');

      ss << "depth=" << std::setw(2) << static_cast<int>(lineage.depth) << ";";
      ss << "fp=";
      ss << std::setw(2) << ((lineage.parent_fingerprint >> 24) & 0xFFu)
         << std::setw(2) << ((lineage.parent_fingerprint >> 16) & 0xFFu)
         << std::setw(2) << ((lineage.parent_fingerprint >> 8) & 0xFFu)
         << std::setw(2) << (lineage.parent_fingerprint & 0xFFu) << ";";
      ss << "child=" << std::setw(8) << lineage.child_number << ";";
      ss << "chaincode=";
      for (const auto byte : chain) {
        ss << std::setw(2) << static_cast<int>(byte);
      }
      ss << ";";
      ss << "key=";
      for (const auto byte : key_bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
      }

      return ss.str();
    };

    const uint64_t priv_prefixes =
        is_testnet ? wallet::hd_private::testnet : wallet::hd_private::mainnet;
    wallet::hd_private priv(ext_str, priv_prefixes);
    if (priv) {
      // Equivalent to Core's CExtKey::Decode master-key lineage check.
      const auto &lineage = priv.lineage();
      if (lineage.depth == 0 &&
          (lineage.parent_fingerprint != 0 || lineage.child_number != 0)) {
        return "INVALID";
      }
      const auto &secret = priv.secret();
      if (!verify_secret(secret))
        return "INVALID";
      data_chunk key_bytes(secret.begin(), secret.end());
      return format_key(lineage, priv.chain_code(), key_bytes);
    }

    const uint32_t pub_prefix =
        is_testnet ? wallet::hd_public::testnet : wallet::hd_public::mainnet;
    wallet::hd_public pub(ext_str, pub_prefix);
    if (pub) {
      // Equivalent to Core's CExtPubKey::Decode master-key lineage check.
      const auto &lineage = pub.lineage();
      if (lineage.depth == 0 &&
          (lineage.parent_fingerprint != 0 || lineage.child_number != 0)) {
        return "INVALID";
      }
      const auto &point = pub.point();
      if (!is_compressed_key(point) || !verify_point(data_slice(point)))
        return "INVALID";
      data_chunk key_bytes(point.begin(), point.end());
      return format_key(lineage, pub.chain_code(), key_bytes);
    }

    return "INVALID";
  } catch (const std::exception &) {
    return "INVALID";
  }
}

std::optional<bool>
LibbitcoinSystem::script_eval(const std::vector<uint8_t> &input_data,
                              unsigned int /*flags*/,
                              size_t /*version*/) const {
  if (input_data.empty()) {
    return std::nullopt;
  }
  data_chunk script_bytes(input_data.begin(), input_data.end());

  const chain::script in_script{script_bytes, false};
  if (!in_script.is_valid()) {
    return false;
  }

  // Uses an 0P_1 scripPubkey to always push truthy, so that script_eval tests
  // whether script executes without error, as oposed to whether it leaves
  // a truth value on stack, which is tested by verify_script target.
  // Concrete divergence: scriptSig=OP_0 → bitcoin core false,
  // libbitcoin (with OP_1) returns true.
  const data_chunk out_bytes{0x51}; // OP_1
  const chain::script out_script{out_bytes, false};

  const chain::transaction tx{
      1u, chain::inputs{{chain::point{}, in_script, chain::max_input_sequence}},
      chain::outputs{}, 0u};

  const auto inputs_ptr = tx.inputs_ptr();
  inputs_ptr->front()->prevout = to_shared(chain::output{0u, out_script});

  const chain::context ctx{chain::flags::no_rules, 0u, 0u, 0u, 0u, 0u};

  using interp = machine::interpreter<machine::contiguous_stack>;
  const auto ec = interp::connect(ctx, tx, 0u, mock_signature_checker());
  return !ec;
}

std::optional<bool> LibbitcoinSystem::verify_script(
    const std::vector<uint8_t> &script_sig,
    const std::vector<uint8_t> &script_pubkey) const {
  if (script_sig.empty() || script_pubkey.empty()) {
    return std::nullopt;
  }

  const chain::script in_script{
      data_chunk(script_sig.begin(), script_sig.end()), false};
  const chain::script out_script{
      data_chunk(script_pubkey.begin(), script_pubkey.end()), false};

  if (!in_script.is_valid() || !out_script.is_valid()) {
    return false;
  }

  const chain::transaction tx{
      1u, chain::inputs{{chain::point{}, in_script, chain::max_input_sequence}},
      chain::outputs{}, 0u};

  const auto inputs_ptr = tx.inputs_ptr();
  inputs_ptr->front()->prevout = to_shared(chain::output{0u, out_script});

  const chain::context ctx{chain::flags::no_rules, 0u, 0u, 0u, 0u, 0u};

  using interp = machine::interpreter<machine::contiguous_stack>;
  const auto ec = interp::connect(ctx, tx, 0u, mock_signature_checker());
  return !ec;
}

} // namespace module
} // namespace bitcoinfuzz
