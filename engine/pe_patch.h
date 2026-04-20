#pragma once
// pe_patch.h — header-cleansing routines applied to the target PE in addition
// to the obfuscator's section injection. Each function takes the full file
// buffer, re-derives DOS/NT pointers internally, and silently skips work it
// cannot perform safely. Designed to be invoked from entry.cpp around the
// existing VM / junk-restore code paths.

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace pe_patch {

inline IMAGE_DOS_HEADER* dos(uint8_t* pe) {
    return reinterpret_cast<IMAGE_DOS_HEADER*>(pe);
}

inline IMAGE_NT_HEADERS64* nt(uint8_t* pe) {
    return reinterpret_cast<IMAGE_NT_HEADERS64*>(pe + dos(pe)->e_lfanew);
}

inline IMAGE_SECTION_HEADER* sections(uint8_t* pe) {
    return IMAGE_FIRST_SECTION(nt(pe));
}

inline uint32_t rva_to_off(uint8_t* pe, uint32_t rva) {
    auto* n = nt(pe);
    auto* s = sections(pe);
    for (WORD i = 0; i < n->FileHeader.NumberOfSections; ++i) {
        uint32_t va = s[i].VirtualAddress;
        uint32_t vsz = s[i].Misc.VirtualSize;
        if (vsz == 0) vsz = s[i].SizeOfRawData;
        if (rva >= va && rva < va + vsz) {
            return s[i].PointerToRawData + (rva - va);
        }
    }
    return 0;
}

inline void clear_timestamps(std::vector<uint8_t>& pe_data) {
    auto* n = nt(pe_data.data());
    n->FileHeader.TimeDateStamp = 0;

    auto& exp = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp.VirtualAddress && exp.Size) {
        uint32_t off = rva_to_off(pe_data.data(), exp.VirtualAddress);
        if (off && off + sizeof(IMAGE_EXPORT_DIRECTORY) <= pe_data.size()) {
            reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pe_data.data() + off)->TimeDateStamp = 0;
        }
    }

    auto& res = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (res.VirtualAddress && res.Size) {
        uint32_t off = rva_to_off(pe_data.data(), res.VirtualAddress);
        if (off && off + sizeof(IMAGE_RESOURCE_DIRECTORY) <= pe_data.size()) {
            reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(pe_data.data() + off)->TimeDateStamp = 0;
        }
    }
}

// Rich header lives between the DOS stub and the PE signature, terminated by
// the literal "Rich" + 4-byte XOR key. We walk back in DWORD steps until we
// find DanS XOR'd with the same key, then zero the entire span.
inline void strip_rich_header(std::vector<uint8_t>& pe_data) {
    uint32_t lfanew = dos(pe_data.data())->e_lfanew;
    if (lfanew < 0x80 || lfanew > pe_data.size()) return;

    uint8_t* p = pe_data.data();
    for (uint32_t i = 0x40; i + 8 <= lfanew; ++i) {
        if (std::memcmp(p + i, "Rich", 4) != 0) continue;

        uint32_t key = *reinterpret_cast<uint32_t*>(p + i + 4);
        for (uint32_t back = 4; back <= i; back += 4) {
            uint32_t v = *reinterpret_cast<uint32_t*>(p + i - back) ^ key;
            if (v == 0x536E6144u /* 'DanS' */) {
                std::memset(p + (i - back), 0, (i + 8) - (i - back));
                return;
            }
        }
        return;
    }
}

inline void wipe_section_names(std::vector<uint8_t>& pe_data) {
    auto* n = nt(pe_data.data());
    auto* s = sections(pe_data.data());
    for (WORD i = 0; i < n->FileHeader.NumberOfSections; ++i) {
        std::memset(s[i].Name, 0, IMAGE_SIZEOF_SHORT_NAME);
    }
}

inline void clear_checksum(std::vector<uint8_t>& pe_data) {
    nt(pe_data.data())->OptionalHeader.CheckSum = 0;
}

// Clears optional-header version metadata. OS/Subsystem versions are LEFT
// alone — the loader rejects images that claim "0.0" for those.
inline void clear_version_info(std::vector<uint8_t>& pe_data) {
    auto& oh = nt(pe_data.data())->OptionalHeader;
    oh.MajorImageVersion  = 0;
    oh.MinorImageVersion  = 0;
    oh.MajorLinkerVersion = 0;
    oh.MinorLinkerVersion = 0;
    oh.Win32VersionValue  = 0;
}

// Heuristic VS_VERSIONINFO scrub: locate well-known UTF-16 keys and zero the
// value string that follows the trailing null + DWORD padding.
inline void wipe_original_filename(std::vector<uint8_t>& pe_data) {
    static const wchar_t* keys[] = {
        L"OriginalFilename", L"InternalName",   L"ProductName",
        L"FileDescription",  L"CompanyName",    L"LegalCopyright",
    };

    uint8_t* base = pe_data.data();
    size_t   total = pe_data.size();

    for (auto* key : keys) {
        size_t klen = 0;
        while (key[klen]) ++klen;
        size_t kbytes = klen * sizeof(wchar_t);
        if (kbytes + sizeof(wchar_t) > total) continue;

        for (size_t i = 0; i + kbytes + sizeof(wchar_t) < total; ++i) {
            if (std::memcmp(base + i, key, kbytes) != 0) continue;
            if (*reinterpret_cast<wchar_t*>(base + i + kbytes) != 0) continue;

            size_t j = i + kbytes;
            int skip = 8;
            while (j + sizeof(wchar_t) < total && skip-- > 0) {
                wchar_t* w = reinterpret_cast<wchar_t*>(base + j);
                if (*w != 0) break;
                j += sizeof(wchar_t);
            }
            int max_zero = 256;
            while (j + sizeof(wchar_t) < total && max_zero-- > 0) {
                wchar_t* w = reinterpret_cast<wchar_t*>(base + j);
                if (*w == 0) break;
                *w = 0;
                j += sizeof(wchar_t);
            }
        }
    }
}

inline void strip_debug_info(std::vector<uint8_t>& pe_data) {
    auto* n = nt(pe_data.data());
    auto& dbg = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!dbg.VirtualAddress || !dbg.Size) return;

    uint32_t off = rva_to_off(pe_data.data(), dbg.VirtualAddress);
    if (!off || off + dbg.Size > pe_data.size()) return;

    uint32_t count = dbg.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    auto* entries = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(pe_data.data() + off);
    for (uint32_t i = 0; i < count; ++i) {
        auto& e = entries[i];
        if (e.PointerToRawData && e.SizeOfData &&
            e.PointerToRawData + e.SizeOfData <= pe_data.size()) {
            std::memset(pe_data.data() + e.PointerToRawData, 0, e.SizeOfData);
        } else if (e.AddressOfRawData && e.SizeOfData) {
            uint32_t doff = rva_to_off(pe_data.data(), e.AddressOfRawData);
            if (doff && doff + e.SizeOfData <= pe_data.size()) {
                std::memset(pe_data.data() + doff, 0, e.SizeOfData);
            }
        }
    }
    std::memset(entries, 0, dbg.Size);
    dbg.VirtualAddress = 0;
    dbg.Size = 0;
}

// Windows resolves DLL imports case-insensitively, so flipping case of the
// imported DLL name strings breaks toolchain fingerprints without breaking
// load. Function name strings are left alone (those ARE case-sensitive).
inline void mutate_import_dll_names(std::vector<uint8_t>& pe_data,
                                    std::mt19937& rng) {
    auto* n = nt(pe_data.data());
    auto& imp = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp.VirtualAddress) return;

    uint32_t off = rva_to_off(pe_data.data(), imp.VirtualAddress);
    if (!off || off + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe_data.size()) return;

    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pe_data.data() + off);
    while (desc->Name != 0 && reinterpret_cast<uint8_t*>(desc) < pe_data.data() + pe_data.size()) {
        uint32_t name_off = rva_to_off(pe_data.data(), desc->Name);
        if (name_off && name_off < pe_data.size()) {
            char* name = reinterpret_cast<char*>(pe_data.data() + name_off);
            for (size_t i = 0; (name_off + i) < pe_data.size() && name[i] != 0; ++i) {
                char c = name[i];
                if (c >= 'a' && c <= 'z' && (rng() & 1)) name[i] = c - 32;
                else if (c >= 'A' && c <= 'Z' && (rng() & 1)) name[i] = c + 32;
            }
        }
        desc++;
    }
}

inline void apply_section_permissions(std::vector<uint8_t>& pe_data) {
    const uint32_t flags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
                           IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE |
                           IMAGE_SCN_CNT_INITIALIZED_DATA;
    auto* n = nt(pe_data.data());
    auto* s = sections(pe_data.data());
    for (WORD i = 0; i < n->FileHeader.NumberOfSections; ++i) {
        s[i].Characteristics = flags;
    }
}

// Zeros data directory entries that are non-essential for loading and would
// otherwise leak provenance (signatures, bindings) or expose unused slots
// scanners key on. Load-critical entries (IMPORT/IAT/EXPORT/RESOURCE/TLS/
// BASE_RELOC/EXCEPTION/DEBUG-already-handled/LOAD_CONFIG) are preserved.
inline void clean_data_directories(std::vector<uint8_t>& pe_data) {
    auto* n = nt(pe_data.data());
    static const int kill[] = {
        IMAGE_DIRECTORY_ENTRY_SECURITY,
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
    };
    for (int idx : kill) {
        n->OptionalHeader.DataDirectory[idx].VirtualAddress = 0;
        n->OptionalHeader.DataDirectory[idx].Size = 0;
    }
}

// Plants a tiny export directory in unused header slack so static scanners
// that bail on "no exports" find something to chew on. Skipped if the file
// already has exports or there isn't enough slack between the section
// header table and the first section's raw data.
inline bool fake_export_table(std::vector<uint8_t>& pe_data) {
    auto* d = dos(pe_data.data());
    auto* n = nt(pe_data.data());
    auto& exp = n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp.VirtualAddress != 0) return false;
    if (n->FileHeader.NumberOfSections == 0) return false;

    uint32_t headers_end = d->e_lfanew + sizeof(IMAGE_NT_HEADERS64)
                           + n->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    uint32_t headers_size = n->OptionalHeader.SizeOfHeaders;
    if (headers_size > pe_data.size()) return false;

    const char* dll_name  = "Argal.dll";
    const char* func_name = "InitializeRuntime";
    size_t dll_len = std::strlen(dll_name) + 1;
    size_t fn_len  = std::strlen(func_name) + 1;
    size_t need = sizeof(IMAGE_EXPORT_DIRECTORY) + dll_len + 4 + 4 + 2 + fn_len;

    if (headers_end + need > headers_size) return false;

    uint8_t* p = pe_data.data() + headers_end;
    uint32_t base_rva = headers_end; // headers map 1:1 in the image
    std::memset(p, 0, need);

    auto* ed = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(p);
    uint32_t off = sizeof(IMAGE_EXPORT_DIRECTORY);

    uint32_t name_rva = base_rva + off;
    std::memcpy(p + off, dll_name, dll_len);
    off += static_cast<uint32_t>(dll_len);

    uint32_t func_arr_rva = base_rva + off;
    *reinterpret_cast<uint32_t*>(p + off) = base_rva; // self-reference
    off += 4;

    uint32_t name_arr_rva = base_rva + off;
    uint32_t name_arr_off = off;
    off += 4;

    uint32_t ord_arr_rva = base_rva + off;
    *reinterpret_cast<uint16_t*>(p + off) = 0;
    off += 2;

    uint32_t fn_name_rva = base_rva + off;
    *reinterpret_cast<uint32_t*>(p + name_arr_off) = fn_name_rva;
    std::memcpy(p + off, func_name, fn_len);

    ed->Characteristics       = 0;
    ed->TimeDateStamp         = 0;
    ed->MajorVersion          = 0;
    ed->MinorVersion          = 0;
    ed->Name                  = name_rva;
    ed->Base                  = 1;
    ed->NumberOfFunctions     = 1;
    ed->NumberOfNames         = 1;
    ed->AddressOfFunctions    = func_arr_rva;
    ed->AddressOfNames        = name_arr_rva;
    ed->AddressOfNameOrdinals = ord_arr_rva;

    exp.VirtualAddress = base_rva;
    exp.Size = static_cast<uint32_t>(need);
    return true;
}

inline void apply_pre_patches(std::vector<uint8_t>& pe_data, std::mt19937& rng) {
    strip_rich_header(pe_data);
    strip_debug_info(pe_data);
    clean_data_directories(pe_data);
    clear_version_info(pe_data);
    wipe_original_filename(pe_data);
    mutate_import_dll_names(pe_data, rng);
}

inline void apply_post_patches(std::vector<uint8_t>& pe_data) {
    wipe_section_names(pe_data);
    apply_section_permissions(pe_data);
    fake_export_table(pe_data);
    clear_timestamps(pe_data);
    clear_checksum(pe_data); // keep last so any earlier patch is reflected
}

} // namespace pe_patch
