#include <cstddef>
#include <cstdint>

extern "C" char *rustreexo_stump_modify(const uint8_t *buffer,
                                        size_t buffer_len);
extern "C" char *rustreexo_stump_update(const uint8_t *add_hashes_flat,
                                        size_t add_count,
                                        const uint8_t *del_hashes_flat,
                                        size_t del_count,
                                        const uint8_t *new_add_hashes_flat,
                                        size_t new_add_count);
extern "C" void rustreexo_free_string(void *ptr);
