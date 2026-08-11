#include <cstdint>

extern "C" char *musig2_key_agg(const uint8_t *seckeys, size_t num_keys);
extern "C" char *musig2_keyagg_ctx(const uint8_t *data, size_t len);
// tweaks: num_tweaks records of 33 bytes each (1 type byte, non-zero for
// x-only, followed by the 32-byte tweak), applied in order. extra_input32 is
// null or 32 bytes mixed into BIP-327 nonce generation.
extern "C" char *musig2_sign_session(const uint8_t *seckeys, size_t num_keys,
                                     const uint8_t *msg32,
                                     const uint8_t *nonce_seeds,
                                     const uint8_t *extra_input32,
                                     const uint8_t *tweaks, size_t num_tweaks);
extern "C" void musig2_free_string(void *ptr);
