#include <string>

extern bool rust_miniscript_from_str(const char* miniscript_str);
extern char* rust_bitcoin_des_block(const uint8_t *data, size_t len);
extern char* rust_bitcoin_prefilledtransaction(const uint8_t *data, size_t len);
