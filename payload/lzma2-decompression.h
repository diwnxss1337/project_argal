#pragma once
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <Windows.h>
#include <compressapi.h>

#pragma comment(lib, "Cabinet.lib")

namespace decompression {

    inline std::vector<uint8_t> decompress(const uint8_t* compressed_data, size_t compressed_size,
                                            size_t original_size) {
        DECOMPRESSOR_HANDLE decompressor = nullptr;
        if (!CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &decompressor)) {
            return {};
        }

        std::vector<uint8_t> output(original_size);
        SIZE_T decompressed_size = 0;
        BOOL ok = Decompress(decompressor, compressed_data, compressed_size,
                             output.data(), output.size(), &decompressed_size);
        CloseDecompressor(decompressor);

        if (!ok) {
            return {};
        }

        output.resize(decompressed_size);
        return output;
    }

} // namespace decompression
