#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <Windows.h>
#include "encryption.h"
#include "lzma2-decompression.h"

namespace restore {

    // Must match the obfuscator's structures exactly
    #pragma pack(push, 1)
    struct RegionDescriptor {
        uint32_t rva;
        uint32_t size;
        uint32_t data_offset;
    };

    struct PackedHeader {
        uint32_t magic;                 // 'ARGL' = 0x4C475241
        uint32_t original_ep_rva;
        uint32_t num_regions;
        uint32_t xor_key_size;
        uint8_t  xor_key[32];
        uint32_t compressed_size;
        uint32_t original_data_size;
    };
    #pragma pack(pop)

    // Find the .argal section in the loaded EXE image and restore original code
    inline bool restore_original_code() {
        // Get the EXE's base address (not the DLL's)
        HMODULE exe_base = GetModuleHandleA(nullptr);
        if (!exe_base) return false;

        auto* base = reinterpret_cast<uint8_t*>(exe_base);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        auto* sections = IMAGE_FIRST_SECTION(nt);
        uint8_t* section_data = nullptr;

        // Find .argal section
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (std::memcmp(sections[i].Name, ".diwnxss\0", 7) == 0) {
                section_data = base + sections[i].VirtualAddress;
                break;
            }
        }
        if (!section_data) return false;

        // Parse header
        auto* hdr = reinterpret_cast<PackedHeader*>(section_data);
        if (hdr->magic != 0x4C475241) return false; // 'ARGL'

        // Get region descriptors
        auto* regions = reinterpret_cast<RegionDescriptor*>(
            section_data + sizeof(PackedHeader));

        // Get encrypted compressed data
        uint8_t* enc_data = section_data + sizeof(PackedHeader)
                            + hdr->num_regions * sizeof(RegionDescriptor);

        // Copy encrypted data (we need a writable copy for decryption)
        std::vector<uint8_t> encrypted(enc_data, enc_data + hdr->compressed_size);

        // Decrypt (XOR)
        crypto::xor_crypt(encrypted.data(), encrypted.size(),
                          hdr->xor_key, hdr->xor_key_size);

        // Decompress
        auto original = decompression::decompress(
            encrypted.data(), encrypted.size(), hdr->original_data_size);

        if (original.empty() || original.size() != hdr->original_data_size) {
            return false;
        }

        // Restore each region
        for (uint32_t i = 0; i < hdr->num_regions; i++) {
            auto& rgn = regions[i];
            uint8_t* target = base + rgn.rva;

            // Make the target region writable
            DWORD old_protect;
            if (!VirtualProtect(target, rgn.size, PAGE_EXECUTE_READWRITE, &old_protect)) {
                continue;
            }

            // Copy original bytes back
            std::memcpy(target, original.data() + rgn.data_offset, rgn.size);

            // Restore original protection
            VirtualProtect(target, rgn.size, old_protect, &old_protect);
        }

        // Flush instruction cache to ensure CPU sees the restored code
        FlushInstructionCache(GetCurrentProcess(), nullptr, 0);

        return true;
    }

} // namespace restore
