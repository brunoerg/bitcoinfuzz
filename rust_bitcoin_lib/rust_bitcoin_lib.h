#include <string>

extern bool rust_miniscript_from_str(const char* miniscript_str);
extern bool rust_bitcoin_script(const uint8_t *data, size_t len);
extern char* rust_bitcoin_psbt(const uint8_t *data, size_t len);
extern char* rust_miniscript_from_str_check_key(const char* miniscript_str);
extern char* rust_bitcoin_des_block(const uint8_t *data, size_t len);
extern char* rust_bitcoin_prefilledtransaction(const uint8_t *data, size_t len);
extern bool rust_bitcoin_addrv2(uint8_t *data, size_t len, uint64_t *count);
extern char* rust_bitcoin_cmpctblocks(uint8_t *data, size_t len);
extern int rust_bitcoin_blocktransactionrequests(const uint8_t *data, size_t len);