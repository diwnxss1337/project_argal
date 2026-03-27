#pragma once
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <Windows.h>
#include <compressapi.h>
#include <string>

#pragma comment(lib, "Cabinet.lib")

namespace compression {

    inline std::vector<uint8_t> compress(const std::vector<uint8_t>& data) {
        if (data.empty()) {
            return {};
        }

        COMPRESSOR_HANDLE compressor = nullptr;
        if (!CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &compressor)) {
            throw std::runtime_error("CreateCompressor failed: " + std::to_string(GetLastError()));
        }

        SIZE_T compressed_size = 0;
        BOOL res = Compress(compressor, (PVOID)data.data(), data.size(), nullptr, 0, &compressed_size);

        DWORD lastError = GetLastError();
        if (!res && lastError != ERROR_INSUFFICIENT_BUFFER) {
            CloseCompressor(compressor);
            throw std::runtime_error("Failed to query compression size. Error: " + std::to_string(lastError));
        }

        std::vector<uint8_t> compressed(compressed_size);
        if (!Compress(compressor, (PVOID)data.data(), data.size(),
            compressed.data(), compressed.size(), &compressed_size)) {
            lastError = GetLastError();
            CloseCompressor(compressor);
            throw std::runtime_error("Compress execution failed. Error: " + std::to_string(lastError));
        }

        CloseCompressor(compressor);
        compressed.resize(compressed_size);
        return compressed;
    }
}