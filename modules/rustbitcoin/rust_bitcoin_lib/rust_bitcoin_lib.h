#include <cstdint>

extern "C" char *rust_bitcoin_script(const uint8_t *data, size_t len);
extern "C" char *rust_bitcoin_des_block(const uint8_t *data, size_t len);
extern "C" char *rust_bitcoin_address_parse(const char *address);
extern "C" char *rust_bitcoin_psbt_parse(const uint8_t *data, size_t len);
extern "C" char *rust_bitcoin_addrv2(const uint8_t *data, size_t len);
extern "C" char *rust_bitcoin_cmpctblocks_parse(const uint8_t *data,
                                                size_t len);
extern "C" void free_c_string(char *ptr);
extern "C" char *rust_bitcoin_parse_p2p_message(const uint8_t *data,
                                                size_t len);
extern "C" char *rust_bitcoin_bip32_master_keygen(const uint8_t *data,
                                                  size_t len);
extern "C" char *
rust_bitcoin_bip32_deserialize_extended_key(const uint8_t *data, size_t len);
extern "C" char *rust_bitcoin_bip32_derive_from_path(const uint8_t *data,
                                                     size_t len);
extern "C" char *rust_bitcoin_decode_ellswift(const uint8_t *data, size_t len);
extern "C" char *rust_bitcoin_roundtrip_ellswift(const uint8_t *data,
                                                 size_t len);
extern "C" char *rust_bitcoin_merkle_root_compute(const uint8_t *data,
                                                  size_t len);
extern "C" char *rust_bitcoin_partial_merkle_tree(const uint8_t *data,
                                                  size_t len);
