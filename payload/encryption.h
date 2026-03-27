#pragma once
#include <cstdint>
#include <cstddef>

namespace crypto {

    inline void xor_crypt(uint8_t* data, size_t size, const uint8_t* key, size_t key_size) {
        for (size_t i = 0; i < size; i++) {
            data[i] ^= key[i % key_size];
        }
    }

} // namespace crypto
