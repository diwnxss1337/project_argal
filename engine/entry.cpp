// credits to claude
// vibecoded code virtualizer/obfuscator
// made by diwness using claude
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <cstddef>   // offsetof
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>

#include "opcode.h"
#include "lzma2-compression.h"
#include "vm_defs.h"
#include "x64_lifter.h"
#include "pe_patch.h"

namespace crypto {
    inline void xor_crypt(uint8_t* data, size_t size, const uint8_t* key, size_t key_size) {
        for (size_t i = 0; i < size; i++) {
            data[i] ^= key[i % key_size];
        }
    }
}

#pragma pack(push, 1)
struct RegionDescriptor {
    uint32_t rva;
    uint32_t size; 
    uint32_t data_offset;
};

struct PackedHeader {
    uint32_t magic;
    uint32_t original_ep_rva;
    uint32_t num_regions;
    uint32_t xor_key_size;
    uint8_t  xor_key[32]; 
    uint32_t compressed_size;
    uint32_t original_data_size;
};
#pragma pack(pop)

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open: " + path);
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(data.data()), sz);
    return data;
}

static void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

static IMAGE_DOS_HEADER* dos_hdr(uint8_t* pe) {
    return reinterpret_cast<IMAGE_DOS_HEADER*>(pe);
}

static IMAGE_NT_HEADERS64* nt_hdr(uint8_t* pe) {
    return reinterpret_cast<IMAGE_NT_HEADERS64*>(pe + dos_hdr(pe)->e_lfanew);
}

static IMAGE_SECTION_HEADER* first_section(uint8_t* pe) {
    return IMAGE_FIRST_SECTION(nt_hdr(pe));
}

static uint32_t rva_to_offset(uint8_t* pe, uint32_t rva) {
    auto* nt = nt_hdr(pe);
    auto* sec = first_section(pe);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
        }
    }
    return rva;
}

static uint32_t align_up(uint32_t val, uint32_t alignment) {
    return (val + alignment - 1) & ~(alignment - 1);
}

static std::vector<uint8_t> build_entry_stub(uint32_t stub_rva,
                                              uint32_t iat_entry_rva,
                                              uint32_t original_ep_rva) {
    std::vector<uint8_t> stub;
    stub.reserve(26);

    // sub rsp, 0x28
    stub.push_back(0x48); stub.push_back(0x83); stub.push_back(0xEC); stub.push_back(0x28);

    // lea rax, [rip + iat_disp]
    int32_t iat_disp = static_cast<int32_t>(iat_entry_rva) - static_cast<int32_t>(stub_rva + 11);
    stub.push_back(0x48); stub.push_back(0x8D); stub.push_back(0x05);
    for (int i = 0; i < 4; i++) stub.push_back((static_cast<uint32_t>(iat_disp) >> (i * 8)) & 0xFF);

    // call qword ptr [rax]
    stub.push_back(0xFF); stub.push_back(0x10);

    // add rsp, 0x28
    stub.push_back(0x48); stub.push_back(0x83); stub.push_back(0xC4); stub.push_back(0x28);
    int32_t oep_disp = static_cast<int32_t>(original_ep_rva) - static_cast<int32_t>(stub_rva + 24);
    stub.push_back(0x48); stub.push_back(0x8D); stub.push_back(0x05);
    for (int i = 0; i < 4; i++) stub.push_back((static_cast<uint32_t>(oep_disp) >> (i * 8)) & 0xFF);

    stub.push_back(0xFF); stub.push_back(0xE0);

    return stub;
}

static uint64_t parse_hex(const std::string& s) {
    return std::stoull(s, nullptr, 16);
}

int main(int argc, char* argv[]) {
    try {
        bool vm_mode = false;
        std::vector<std::string> args;
        for (int i = 1; i < argc; ++i) {
            if (std::string(argv[i]) == "--vm") vm_mode = true;
            else args.push_back(argv[i]);
        }

        if (args.size() < 5 || (args.size() - 3) % 2 != 0) {
            std::cout << "Argal Code Obfuscator(x64 only)\n\n"
                      << "Usage:\n"
                      << "  Obfuscator.exe [--vm] <target.exe> <payload.dll> <output.exe> <start_rva> <end_rva> [...]\n\n"
                      << "  --vm   Virtualize the region (custom VM) instead of junk+restore.\n"
                      << "  RVAs are relative to image base (hex, 0x prefix OK).\n\n"
                      << "Example:\n"
                      << "  Obfuscator.exe --vm app.exe payload.dll app_obf.exe 0x1000 0x1200\n";
            return 1;
        }

        std::string target_path  = args[0];
        std::string payload_path = args[1];
        std::string output_path  = args[2];

        std::cout << "[*] reading pe\n";
        auto pe_data = read_file(target_path);

        std::cout << "[*] payload loaded\n";
        auto payload_dll = read_file(payload_path);

        if (pe_data.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))
            throw std::runtime_error("File too small to be a valid PE");

        auto* dos = dos_hdr(pe_data.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            throw std::runtime_error("Invalid DOS signature");

        auto* nt = nt_hdr(pe_data.data());
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            throw std::runtime_error("Invalid NT signature");
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
            throw std::runtime_error("Not an x64 PE");
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            throw std::runtime_error("Not a PE64 optional header");

        uint64_t image_base = nt->OptionalHeader.ImageBase;
        uint32_t original_ep = nt->OptionalHeader.AddressOfEntryPoint;
        uint32_t section_align = nt->OptionalHeader.SectionAlignment;
        uint32_t file_align = nt->OptionalHeader.FileAlignment;

        std::cout << "[*] imagebase -> 0x" << std::hex << image_base << "\n";
        std::cout << "[*] ep -> 0x" << original_ep << "\n";
        std::cout << std::dec;

        struct FuncRange { uint32_t start_rva; uint32_t end_rva; };
        std::vector<FuncRange> ranges;
        for (size_t i = 3; i + 1 < args.size(); i += 2) {
            uint64_t start_va = parse_hex(args[i]);
            uint64_t end_va   = parse_hex(args[i + 1]);
            if (start_va > image_base) start_va -= image_base;
            if (end_va > image_base)   end_va   -= image_base;
            ranges.push_back({ static_cast<uint32_t>(start_va), static_cast<uint32_t>(end_va) });
        }

        std::cout << "[*] applying pre-patches (rich/debug/version/imports)\n";
        {
            std::mt19937 patch_rng(std::random_device{}());
            pe_patch::apply_pre_patches(pe_data, patch_rng);
        }
        dos = dos_hdr(pe_data.data());
        nt  = nt_hdr(pe_data.data());

        if (vm_mode) {
            // Seed the RNG with multiple entropy sources so each build
            // produces a completely different opcode map and stub layout.
            std::random_device rd;
            std::seed_seq seed_seq{
                rd(), rd(), rd(), rd(),
                static_cast<uint32_t>(std::chrono::high_resolution_clock::now()
                    .time_since_epoch().count()),
                static_cast<uint32_t>(std::chrono::high_resolution_clock::now()
                    .time_since_epoch().count() >> 32),
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&rd)),
                static_cast<uint32_t>(GetCurrentProcessId()),
            };
            std::mt19937 rng(seed_seq);

            // Generate the XOR key used for opcode map derivation, then
            // scramble it further with a second mixing pass.
            uint8_t xor_key[32];
            for (auto& b : xor_key) b = static_cast<uint8_t>(rng());
            // Extra mixing: fold timestamp bytes into the key
            {
                uint64_t ts = std::chrono::high_resolution_clock::now()
                    .time_since_epoch().count();
                for (int i = 0; i < 32; i++)
                    xor_key[i] ^= static_cast<uint8_t>((ts >> ((i % 8) * 8)) & 0xFF)
                                ^ static_cast<uint8_t>(rng() & 0xFF);
            }

            uint8_t opmap[128], oprev[256];
            lifter::build_opcode_map(xor_key, opmap, oprev);
            struct VmRegionInfo {
                uint32_t original_rva;
                uint32_t original_size;
                uint32_t bytecode_offset;
            };
            std::vector<VmRegionInfo> vm_regions;
            std::vector<uint8_t> all_bytecode;

            for (auto& r : ranges) {
                uint32_t size = r.end_rva - r.start_rva + 1;
                uint32_t foff = rva_to_offset(pe_data.data(), r.start_rva);
                if (foff + size > pe_data.size())
                    throw std::runtime_error("VM region exceeds file bounds");

                uint64_t region_rip = image_base + r.start_rva;
                std::cout << "[vm] lifting 0x" << std::hex << r.start_rva
                          << " - 0x" << r.end_rva
                          << " (" << std::dec << size << " bytes)\n";

                auto res = lifter::lift_region(pe_data.data() + foff, size,
                                               region_rip, opmap, image_base);
                std::cout << "[vm] bytecode: " << res.bytecode.size()
                          << " bytes (" << res.failed_insns << " native fallbacks)\n";

                VmRegionInfo vri;
                vri.original_rva    = r.start_rva;
                vri.original_size   = size;
                vri.bytecode_offset = static_cast<uint32_t>(all_bytecode.size());

                all_bytecode.insert(all_bytecode.end(),
                                    res.bytecode.begin(), res.bytecode.end());
                vm_regions.push_back(std::move(vri));
            }

            auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            std::vector<IMAGE_IMPORT_DESCRIPTOR> old_imports;
            if (import_dir.VirtualAddress != 0) {
                uint32_t imp_off = rva_to_offset(pe_data.data(), import_dir.VirtualAddress);
                auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pe_data.data() + imp_off);
                while (imp->Name != 0) { old_imports.push_back(*imp++); }
            }
            size_t off_vmhdr    = sizeof(PackedHeader);
            size_t vm_hdr_size  = sizeof(VmHeader);
            size_t off_vmregions = off_vmhdr + vm_hdr_size;
            size_t off_stubs    = off_vmregions + vm_regions.size() * sizeof(VmRegionDesc);
            off_stubs = (off_stubs + 15) & ~15ULL;

            std::vector<size_t> stub_offsets;
            size_t stubs_total = 0;
            for (size_t i = 0; i < vm_regions.size(); ++i) {
                stub_offsets.push_back(stubs_total);
                stubs_total += lifter::kVmStubSize;
            }

            size_t off_bytecode  = off_stubs + stubs_total;
            off_bytecode = (off_bytecode + 15) & ~15ULL;
            size_t off_imports   = off_bytecode + all_bytecode.size();
            off_imports = (off_imports + 3) & ~3ULL;

            size_t imp_arr_size  = (old_imports.size() + 1 + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
            size_t off_dllname   = off_imports + imp_arr_size;
            const char* dll_name = "payload.dll";
            size_t dll_name_len  = strlen(dll_name) + 1;

            const char* fn_nigga  = "Nigga";
            const char* fn_vm     = "ArgalVmInterp";
            size_t off_hint_nigga = off_dllname + dll_name_len;
            if (off_hint_nigga % 2) off_hint_nigga++;
            size_t hint_nigga_size = 2 + strlen(fn_nigga) + 1;
            if (hint_nigga_size % 2) hint_nigga_size++;
            size_t off_hint_vm    = off_hint_nigga + hint_nigga_size;
            size_t hint_vm_size   = 2 + strlen(fn_vm) + 1;
            if (hint_vm_size % 2) hint_vm_size++;

            size_t off_int  = off_hint_vm + hint_vm_size;
            size_t int_size = 3 * sizeof(IMAGE_THUNK_DATA64);
            size_t off_iat  = off_int + int_size;
            size_t iat_size = 3 * sizeof(IMAGE_THUNK_DATA64);
            size_t off_ep_stub = off_iat + iat_size;
            size_t ep_stub_sz  = 26;
            size_t sec_raw = off_ep_stub + ep_stub_sz;
            auto* sections = first_section(pe_data.data());
            WORD num_sections = nt->FileHeader.NumberOfSections;
            auto& last_sec = sections[num_sections - 1];
            uint32_t new_rva  = align_up(last_sec.VirtualAddress + last_sec.Misc.VirtualSize, section_align);
            uint32_t new_foff = align_up(last_sec.PointerToRawData + last_sec.SizeOfRawData, file_align);
            uint32_t new_vsz  = align_up(static_cast<uint32_t>(sec_raw), section_align);
            uint32_t new_fsz  = align_up(static_cast<uint32_t>(sec_raw), file_align);

            uint32_t headers_end = dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64)
                                   + num_sections * sizeof(IMAGE_SECTION_HEADER);
            if (headers_end + sizeof(IMAGE_SECTION_HEADER) > sections[0].PointerToRawData)
                throw std::runtime_error("No room for VM section header");

            std::vector<uint8_t> sec(new_fsz, 0);
            PackedHeader phdr{};
            phdr.magic = 0x4C475241u;
            phdr.original_ep_rva = original_ep;
            phdr.num_regions = 0;
            phdr.xor_key_size = 32;
            memcpy(phdr.xor_key, xor_key, 32);
            phdr.compressed_size = 0;
            phdr.original_data_size = 0;
            memcpy(sec.data(), &phdr, sizeof(phdr));
            VmHeader vmhdr{};
            vmhdr.magic = 0x4D565241u; // 'ARVM'
            memcpy(vmhdr.opcode_map, opmap, 128);
            memcpy(vmhdr.opcode_rev, oprev, 256);
            vmhdr.bytecode_rva   = new_rva + static_cast<uint32_t>(off_bytecode);
            vmhdr.bytecode_size  = static_cast<uint32_t>(all_bytecode.size());
            vmhdr.num_vm_regions = static_cast<uint32_t>(vm_regions.size());
            memcpy(sec.data() + off_vmhdr, &vmhdr, sizeof(vmhdr));
            uint32_t vm_iat_rva = new_rva + static_cast<uint32_t>(off_iat) + sizeof(IMAGE_THUNK_DATA64);

            for (size_t i = 0; i < vm_regions.size(); ++i) {
                auto& vri = vm_regions[i];
                uint32_t stub_rva_in_sec = new_rva + static_cast<uint32_t>(off_stubs + stub_offsets[i]);

                VmRegionDesc vrd{};
                vrd.original_rva    = vri.original_rva;
                vrd.bytecode_offset = vri.bytecode_offset;
                vrd.vm_entry_rva    = stub_rva_in_sec;
                size_t vrd_off = off_vmregions + i * sizeof(VmRegionDesc);
                memcpy(sec.data() + vrd_off, &vrd, sizeof(vrd));
                uint32_t bc_rva     = new_rva + static_cast<uint32_t>(off_bytecode + vri.bytecode_offset);
                uint32_t revmap_rva = new_rva + static_cast<uint32_t>(off_vmhdr)
                                      + static_cast<uint32_t>(offsetof(VmHeader, opcode_rev));
                auto stub = lifter::build_vm_entry_stub(
                    stub_rva_in_sec, bc_rva, revmap_rva, vm_iat_rva, rng);
                size_t stub_in_sec = off_stubs + stub_offsets[i];
                memcpy(sec.data() + stub_in_sec, stub.data(), stub.size());
                uint32_t foff = rva_to_offset(pe_data.data(), vri.original_rva);
                if (foff + 5 <= pe_data.size() && vri.original_size >= 5) {
                    int32_t disp = static_cast<int32_t>(stub_rva_in_sec)
                                 - static_cast<int32_t>(vri.original_rva + 5);
                    pe_data[foff + 0] = 0xE9;
                    uint32_t ud = static_cast<uint32_t>(disp);
                    pe_data[foff + 1] = ud & 0xFF;
                    pe_data[foff + 2] = (ud >> 8)  & 0xFF;
                    pe_data[foff + 3] = (ud >> 16) & 0xFF;
                    pe_data[foff + 4] = (ud >> 24) & 0xFF;
                    // Fill remaining space with anti-disasm junk instead of NOPs
                    // This confuses x64dbg's linear sweep disassembler in the dead zone
                    uint32_t junk_size = vri.original_size - 5;
                    if (junk_size > 0) {
                        opcode::generate_antidisasm_junk(
                            pe_data.data() + foff + 5, junk_size, rng);
                    }
                }
                std::cout << "[vm] region " << i << " stub @ 0x" << std::hex
                          << stub_rva_in_sec << std::dec << "\n";
            }

            memcpy(sec.data() + off_bytecode, all_bytecode.data(), all_bytecode.size());

            auto* nimp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(sec.data() + off_imports);
            for (size_t i = 0; i < old_imports.size(); ++i) nimp[i] = old_imports[i];
            auto& pimp = nimp[old_imports.size()];
            memset(&pimp, 0, sizeof(pimp));
            pimp.Name = new_rva + static_cast<uint32_t>(off_dllname);
            pimp.OriginalFirstThunk = new_rva + static_cast<uint32_t>(off_int);
            pimp.FirstThunk         = new_rva + static_cast<uint32_t>(off_iat);
            memset(&nimp[old_imports.size() + 1], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

            memcpy(sec.data() + off_dllname, dll_name, dll_name_len);

            uint16_t hint = 0;
            memcpy(sec.data() + off_hint_nigga, &hint, 2);
            memcpy(sec.data() + off_hint_nigga + 2, fn_nigga, strlen(fn_nigga) + 1);

            memcpy(sec.data() + off_hint_vm, &hint, 2);
            memcpy(sec.data() + off_hint_vm + 2, fn_vm, strlen(fn_vm) + 1);
            auto* INT = reinterpret_cast<IMAGE_THUNK_DATA64*>(sec.data() + off_int);
            INT[0].u1.AddressOfData = new_rva + static_cast<uint32_t>(off_hint_nigga);
            INT[1].u1.AddressOfData = new_rva + static_cast<uint32_t>(off_hint_vm);
            INT[2].u1.AddressOfData = 0;

            auto* IAT = reinterpret_cast<IMAGE_THUNK_DATA64*>(sec.data() + off_iat);
            IAT[0].u1.AddressOfData = new_rva + static_cast<uint32_t>(off_hint_nigga);
            IAT[1].u1.AddressOfData = new_rva + static_cast<uint32_t>(off_hint_vm);
            IAT[2].u1.AddressOfData = 0;

            uint32_t ep_stub_rva = new_rva + static_cast<uint32_t>(off_ep_stub);
            uint32_t iat_nigga_rva = new_rva + static_cast<uint32_t>(off_iat); // IAT[0]
            auto ep_stub = build_entry_stub(ep_stub_rva, iat_nigga_rva, original_ep);
            memcpy(sec.data() + off_ep_stub, ep_stub.data(), ep_stub.size());

            pe_data.resize(new_foff + new_fsz, 0);
            dos = dos_hdr(pe_data.data());
            nt  = nt_hdr(pe_data.data());
            sections = first_section(pe_data.data());

            auto& nsec = sections[num_sections];
            memset(&nsec, 0, sizeof(nsec));
            memcpy(nsec.Name, ".diwnxss", 8);
            nsec.Misc.VirtualSize = static_cast<uint32_t>(sec_raw);
            nsec.VirtualAddress   = new_rva;
            nsec.SizeOfRawData    = new_fsz;
            nsec.PointerToRawData = new_foff;
            nsec.Characteristics  = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
                                    IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA |
                                    IMAGE_SCN_CNT_CODE;
            memcpy(pe_data.data() + new_foff, sec.data(), new_fsz);

            nt->FileHeader.NumberOfSections = num_sections + 1;
            nt->OptionalHeader.SizeOfImage  = new_rva + new_vsz;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
                new_rva + static_cast<uint32_t>(off_imports);
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
                static_cast<uint32_t>(imp_arr_size);
            nt->OptionalHeader.AddressOfEntryPoint = ep_stub_rva;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};

            std::cout << "[*] applying post-patches (names/perms/export/timestamps/checksum)\n";
            pe_patch::apply_post_patches(pe_data);

            write_file(output_path, pe_data);
            std::cout << "[+] vm done.\n";
            return 0;
        }

        std::mt19937 rng(std::random_device{}());
        std::vector<uint8_t> original_bytes;
        std::vector<RegionDescriptor> region_descs;

        for (auto& r : ranges) {
            uint32_t size = r.end_rva - r.start_rva + 1;
            uint32_t file_offset = rva_to_offset(pe_data.data(), r.start_rva);

            if (file_offset + size > pe_data.size())
                throw std::runtime_error("Function range exceeds file bounds");

            std::cout << "[*] obfuscating 0x" << std::hex << r.start_rva
                      << " - 0x" << r.end_rva << "\n";

            RegionDescriptor desc;
            desc.rva = r.start_rva;
            desc.size = size;
            desc.data_offset = static_cast<uint32_t>(original_bytes.size());
            region_descs.push_back(desc);

            original_bytes.insert(original_bytes.end(),
                                  pe_data.data() + file_offset,
                                  pe_data.data() + file_offset + size);

            auto junk = opcode::generate_obfuscated_code(size, rng);
            std::memcpy(pe_data.data() + file_offset, junk.data(), size);
        }

        std::cout << "[*] compressing...\n";
        auto compressed = compression::compress(original_bytes);
        std::cout << "[*] compressed\n";

        uint8_t xor_key[32];
        for (auto& b : xor_key) b = static_cast<uint8_t>(rng());
        crypto::xor_crypt(compressed.data(), compressed.size(), xor_key, 32);
        std::cout << "[*] applied the enc\n";

        auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        std::vector<IMAGE_IMPORT_DESCRIPTOR> old_imports;

        if (import_dir.VirtualAddress != 0) {
            uint32_t imp_offset = rva_to_offset(pe_data.data(), import_dir.VirtualAddress);
            auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pe_data.data() + imp_offset);
            while (imp->Name != 0) {
                old_imports.push_back(*imp);
                imp++;
            }
        }
        std::cout << "[*] patched DOS\n";

        size_t off_header     = 0;
        size_t off_regions    = off_header + sizeof(PackedHeader);
        size_t off_compressed = off_regions + region_descs.size() * sizeof(RegionDescriptor);
        size_t off_imports    = off_compressed + compressed.size();

        size_t import_array_size = (old_imports.size() + 1 + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
        size_t off_dll_name   = off_imports + import_array_size;

        const char* dll_name  = "payload.dll";
        size_t dll_name_len   = std::strlen(dll_name) + 1;
        size_t off_hint_name  = off_dll_name + dll_name_len;

        const char* func_name = "Nigga";
        size_t hint_name_size = 2 + std::strlen(func_name) + 1;
        if (hint_name_size % 2 != 0) hint_name_size++;

        size_t off_int        = off_hint_name + hint_name_size;
        size_t int_size       = 2 * sizeof(IMAGE_THUNK_DATA64); // one entry + null
        size_t off_iat        = off_int + int_size;
        size_t iat_size       = 2 * sizeof(IMAGE_THUNK_DATA64);
        size_t off_stub       = off_iat + iat_size;
        size_t stub_size      = 26;
        size_t section_raw_size = off_stub + stub_size;

        auto* sections = first_section(pe_data.data());
        WORD num_sections = nt->FileHeader.NumberOfSections;
        auto& last_sec = sections[num_sections - 1];

        uint32_t new_sec_rva = align_up(last_sec.VirtualAddress + last_sec.Misc.VirtualSize,
                                         section_align);
        uint32_t new_sec_file_offset = align_up(last_sec.PointerToRawData + last_sec.SizeOfRawData,
                                                 file_align);
        uint32_t new_sec_vsize = align_up(static_cast<uint32_t>(section_raw_size), section_align);
        uint32_t new_sec_fsize = align_up(static_cast<uint32_t>(section_raw_size), file_align);

        uint32_t headers_end = dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64)
                               + num_sections * sizeof(IMAGE_SECTION_HEADER);
        uint32_t first_sec_offset = sections[0].PointerToRawData;
        if (headers_end + sizeof(IMAGE_SECTION_HEADER) > first_sec_offset)
            throw std::runtime_error("No room for additional section header");

        std::vector<uint8_t> sec_data(new_sec_fsize, 0);

        PackedHeader hdr{};
        hdr.magic = 0x4C475241; // 'ARGL'
        hdr.original_ep_rva = original_ep;
        hdr.num_regions = static_cast<uint32_t>(region_descs.size());
        hdr.xor_key_size = 32;
        std::memcpy(hdr.xor_key, xor_key, 32);
        hdr.compressed_size = static_cast<uint32_t>(compressed.size());
        hdr.original_data_size = static_cast<uint32_t>(original_bytes.size());
        std::memcpy(sec_data.data() + off_header, &hdr, sizeof(hdr));

        std::memcpy(sec_data.data() + off_regions, region_descs.data(),
                    region_descs.size() * sizeof(RegionDescriptor));

        std::memcpy(sec_data.data() + off_compressed, compressed.data(), compressed.size());

        auto* new_imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(sec_data.data() + off_imports);
        for (size_t i = 0; i < old_imports.size(); i++) {
            new_imp[i] = old_imports[i];
        }
        auto& payload_imp = new_imp[old_imports.size()];
        std::memset(&payload_imp, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        payload_imp.Name = new_sec_rva + static_cast<uint32_t>(off_dll_name);
        payload_imp.OriginalFirstThunk = new_sec_rva + static_cast<uint32_t>(off_int);
        payload_imp.FirstThunk = new_sec_rva + static_cast<uint32_t>(off_iat);
        payload_imp.TimeDateStamp = 0;
        payload_imp.ForwarderChain = 0;
        std::memset(&new_imp[old_imports.size() + 1], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        std::memcpy(sec_data.data() + off_dll_name, dll_name, dll_name_len);
        uint16_t hint = 0;
        std::memcpy(sec_data.data() + off_hint_name, &hint, 2);
        std::memcpy(sec_data.data() + off_hint_name + 2, func_name, std::strlen(func_name) + 1);

        uint32_t hint_name_rva = new_sec_rva + static_cast<uint32_t>(off_hint_name);
        auto* int_entries = reinterpret_cast<IMAGE_THUNK_DATA64*>(sec_data.data() + off_int);
        int_entries[0].u1.AddressOfData = hint_name_rva;
        int_entries[1].u1.AddressOfData = 0; // null terminator
        auto* iat_entries = reinterpret_cast<IMAGE_THUNK_DATA64*>(sec_data.data() + off_iat);
        iat_entries[0].u1.AddressOfData = hint_name_rva;
        iat_entries[1].u1.AddressOfData = 0;

        uint32_t stub_rva = new_sec_rva + static_cast<uint32_t>(off_stub);
        uint32_t iat_entry_rva = new_sec_rva + static_cast<uint32_t>(off_iat);
        auto stub = build_entry_stub(stub_rva, iat_entry_rva, original_ep);
        std::memcpy(sec_data.data() + off_stub, stub.data(), stub.size());

        pe_data.resize(new_sec_file_offset + new_sec_fsize, 0);

        dos = dos_hdr(pe_data.data());
        nt = nt_hdr(pe_data.data());
        sections = first_section(pe_data.data());

        auto& new_sec_hdr = sections[num_sections];
        std::memset(&new_sec_hdr, 0, sizeof(IMAGE_SECTION_HEADER));
        std::memcpy(new_sec_hdr.Name, ".diwnxss\0", 7);
        new_sec_hdr.Misc.VirtualSize = static_cast<uint32_t>(section_raw_size);
        new_sec_hdr.VirtualAddress = new_sec_rva;
        new_sec_hdr.SizeOfRawData = new_sec_fsize;
        new_sec_hdr.PointerToRawData = new_sec_file_offset;
        new_sec_hdr.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
                                      IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA |
                                      IMAGE_SCN_CNT_CODE;

        std::memcpy(pe_data.data() + new_sec_file_offset, sec_data.data(), new_sec_fsize);
        nt->FileHeader.NumberOfSections = num_sections + 1;
        nt->OptionalHeader.SizeOfImage = new_sec_rva + new_sec_vsize;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
            new_sec_rva + static_cast<uint32_t>(off_imports);
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
            static_cast<uint32_t>(import_array_size);
        nt->OptionalHeader.AddressOfEntryPoint = stub_rva;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

        std::cout << "[*] applying post-patches (names/perms/export/timestamps/checksum)\n";
        pe_patch::apply_post_patches(pe_data);

        write_file(output_path, pe_data);
        std::cout << "[+] done.\n";

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
}
