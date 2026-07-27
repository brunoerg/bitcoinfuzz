#pragma once

#include "driver.h"
#include <bitcoinfuzz/module_registry.h>
#include <bitcoinfuzz/modulelogger.h>
#include <cstdlib>
#include <iostream>
#include <memory>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#include <sanitizer/lsan_interface.h>
#define BITCOINFUZZ_LSAN_IGNORE(ptr) __lsan_ignore_object(ptr)
#else
#define BITCOINFUZZ_LSAN_IGNORE(ptr)
#endif
#elif defined(__SANITIZE_ADDRESS__)
#include <sanitizer/lsan_interface.h>
#define BITCOINFUZZ_LSAN_IGNORE(ptr) __lsan_ignore_object(ptr)
#else
#define BITCOINFUZZ_LSAN_IGNORE(ptr)
#endif

#ifdef BITCOIN_CORE
#include <modules/bitcoin/module.h>
#endif

#ifdef RUST_BITCOIN
#include <modules/rustbitcoin/module.h>
#endif

#ifdef RUST_PSBT
#include <modules/rustpsbt/module.h>
#endif

#ifdef RUST_MINISCRIPT
#include <modules/rustminiscript/module.h>
#endif

#ifdef TINY_MINISCRIPT
#include <modules/tinyminiscript/module.h>
#endif

#ifdef BITCOINERLAB_MINISCRIPT
#include <modules/bitcoinerlabminiscript/module.h>
#endif

#ifdef BTCD
#include <modules/btcd/module.h>
#endif

#ifdef GOCOIN
#include <modules/gocoin/module.h>
#endif

#ifdef NBITCOIN
#include <modules/nbitcoin/module.h>
#endif

#ifdef LND
#include <modules/lnd/module.h>
#endif

#ifdef LDK
#include <modules/ldk/module.h>
#endif

#ifdef ECLAIR
#include <modules/eclair/module.h>
#endif

#ifdef NLIGHTNING
#include <modules/nlightning/module.h>
#endif

#ifdef PYBITCOINKERNEL
#include <modules/pybitcoinkernel/module.h>
#endif

#ifdef RUSTBITCOINKERNEL
#include <modules/rustbitcoinkernel/module.h>
#endif

#ifdef BITCOINKERNEL
#include <modules/bitcoinkernel/module.h>
#endif

#ifdef BITCOINKERNEL_VARIANT
#include <modules/bitcoinkernelvariant/module.h>
#endif

#ifdef EMBIT
#include <modules/embit/module.h>
#endif

#ifdef CLIGHTNING
#include <modules/clightning/module.h>
#endif

#ifdef LIGHTNING_KMP
#include <modules/lightningkmp/module.h>
#endif

#ifdef BITCOINJ
#include <modules/bitcoinj/module.h>
#endif

#ifdef BITCOINS
#include <modules/bitcoins/module.h>
#endif

#ifdef DECRED_SECP256K1
#include <modules/decredsecp256k1/module.h>
#endif

#ifdef SECP256K1
#include <modules/secp256k1/module.h>
#endif

#ifdef NBITCOIN_SECP256K1
#include <modules/nbitcoinsecp256k1/module.h>
#endif

#ifdef RUST_K256
#include <modules/rustk256/module.h>
#endif

#ifdef LIBWALLY_CORE
#include <modules/libwallycore/module.h>
#endif

#ifdef RUSTREEXO
#include <modules/rustreexo/module.h>
#endif

#ifdef UTREEXO
#include <modules/utreexo/module.h>
#endif

#ifdef PYCOIN
#include <modules/pycoin/module.h>
#endif

#ifdef LIBBITCOIN_SYSTEM
#include <modules/libbitcoinsystem/module.h>
#endif

#ifdef RUST_MUSIG2
#include <modules/rustmusig2/module.h>
#endif

#ifdef RUSTCRYPTO_AES
#include <modules/rustcryptoaes/module.h>
#endif

#ifdef BOOST_MULTI_INDEX
#include <modules/boostmultiindex/module.h>
#endif

#ifdef TMI2
#include <modules/tmi2/module.h>
#endif

#ifdef CUSTOM_MUTATOR_BOLT12_OFFER
#include <custommutator/mutators/bolt12_offer.h>
#endif

#ifdef CUSTOM_MUTATOR_P2P_MESSAGE
#include <custommutator/mutators/p2p_message.h>
#endif

#ifdef CUSTOM_MUTATOR_ONION
#include <custommutator/mutators/onion.h>
#endif

#ifdef CUSTOM_MUTATOR_P2P_LIGHTNING_MESSAGE
#include <custommutator/mutators/p2p_lightning_message.h>
#endif

#ifdef CUSTOM_MUTATOR_BOLT11
#include <custommutator/mutators/bolt11.h>
#endif

#ifdef CUSTOM_MUTATOR_SECP256K1_SIGNATURE
#include <custommutator/mutators/secp256k1_signature.h>
#endif

#ifdef CUSTOM_MUTATOR_EXTENDED_KEY
#include <custommutator/mutators/extended_key.h>
#endif

#ifdef CUSTOM_MUTATOR_SCHNORR_SIGNATURE
#include <custommutator/mutators/schnorr_signature.h>
#endif

namespace bitcoinfuzz {

inline void InitializeRegistry() {
  std::string error = ModuleRegistry::instance().initialize();
  if (!error.empty()) {
    std::cerr << error << std::endl;
    std::abort();
  }
}

inline void LoadModules([[maybe_unused]] std::shared_ptr<Driver> driver,
                        ModuleLogger &module_logger) {
  [[maybe_unused]] auto &registry = ModuleRegistry::instance();

#define MODULE_ENTRY(Flag, Name, Class)                                        \
  if (registry.isEnabled(Name))                                                \
    driver->LoadModule(std::make_shared<bitcoinfuzz::module::Class>());
// CGo modules use a no-op deleter: the Go runtime conflicts with ASAN during
// C++ destructor teardown on exit, causing bad-free false positives.
// Intentionally leaking at exit is safe for the fuzzer.
#define CGO_MODULE_ENTRY(Flag, Name, Class)                                    \
  if (registry.isEnabled(Name)) {                                              \
    auto *raw_ptr = new bitcoinfuzz::module::Class();                          \
    BITCOINFUZZ_LSAN_IGNORE(raw_ptr);                                          \
    driver->LoadModule(std::shared_ptr<bitcoinfuzz::module::Class>(            \
        raw_ptr, [](bitcoinfuzz::module::Class *) {}));                        \
  }
#include "module_defs.h"
#undef MODULE_ENTRY
#undef CGO_MODULE_ENTRY

#ifdef CUSTOM_MUTATOR_BOLT11
  module_logger.addCustomMutator("BOLT11 Bech32 Custom Mutator");
#endif

#ifdef CUSTOM_MUTATOR_SECP256K1_SIGNATURE
  module_logger.addCustomMutator("SECP256K1 Signature Custom Mutator");
#endif

#ifdef CUSTOM_MUTATOR_BOLT12_OFFER
  module_logger.addCustomMutator("BOLT12 Offer/Invoice Custom Mutator");
#endif

#ifdef CUSTOM_MUTATOR_P2P_MESSAGE
  module_logger.addCustomMutator("Bitcoin P2P Message Custom Mutator");
#endif

#ifdef CUSTOM_MUTATOR_ONION
  module_logger.addCustomMutator("Onion Custom Mutator");
#endif

#ifdef CUSTOM_MUTATOR_P2P_LIGHTNING_MESSAGE
  module_logger.addCustomMutator("Lightning P2P Message Custom Mutator");
#endif

#ifdef CUSTOM_MUTATOR_EXTENDED_KEY
  module_logger.addCustomMutator("Extended Key Base58 Custom Mutator");
#endif

#ifdef CUSTOM_MUTATOR_SCHNORR_SIGNATURE
  module_logger.addCustomMutator("Schnorr Signature Custom Mutator");
#endif

  module_logger.logModules();
}

} // namespace bitcoinfuzz
