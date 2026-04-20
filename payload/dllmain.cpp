#include <Windows.h>
#include <cstdint>
#include <cstring>
#include "restore_opcodes.h"
#include "vm_interpreter.h"

static uint32_t g_crc_table[256];

static void build_crc_table() {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int b = 0; b < 8; ++b)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_table[i] = c;
    }
}

static __declspec(noinline) uint32_t crc32_buf(const uint8_t* p, size_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    while (n--) crc = g_crc_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

struct SecGuard {
    const uint8_t* base;
    size_t         size;
    uint32_t       expected_crc;
};

static SecGuard g_guards[2];
static int      g_nguards = 0;
static HANDLE   g_watchdog_handle = nullptr;

static __declspec(noinline) __declspec(noreturn) void tamper_detected() {
    TerminateProcess(GetCurrentProcess(), 0xC0DECAFE);
    __assume(0);
}

static __declspec(noinline) bool check_integrity() {
    for (int i = 0; i < g_nguards; ++i)
        if (crc32_buf(g_guards[i].base, g_guards[i].size) != g_guards[i].expected_crc)
            return false;
    return true;
}

static DWORD WINAPI watchdog_thread(LPVOID) {
    for (;;) {
        Sleep(400);
        if (!check_integrity()) tamper_detected();
    }
}

static void init_tamper_guards() {
    build_crc_table();

    HMODULE hmod = GetModuleHandleW(nullptr);
    if (!hmod) return;

    auto* dos = (IMAGE_DOS_HEADER*)hmod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)hmod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    g_nguards = 0;

    // Section names are wiped by the engine, so derive the code-region guard
    // from the optional header's BaseOfCode/SizeOfCode (set at link time and
    // preserved through obfuscation). The second guard covers the import
    // descriptor block, which catches IAT-rewriting tools.
    uint32_t code_rva = nt->OptionalHeader.BaseOfCode;
    uint32_t code_sz  = nt->OptionalHeader.SizeOfCode;
    if (code_rva && code_sz) {
        const uint8_t* base = (const uint8_t*)hmod + code_rva;
        g_guards[g_nguards++] = { base, code_sz, crc32_buf(base, code_sz) };
    }

    auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress && imp_dir.Size && g_nguards < 2) {
        const uint8_t* base = (const uint8_t*)hmod + imp_dir.VirtualAddress;
        g_guards[g_nguards++] = { base, imp_dir.Size, crc32_buf(base, imp_dir.Size) };
    }

    if (g_nguards > 0) {
        HANDLE h = CreateThread(nullptr, 0, watchdog_thread, nullptr, 0, nullptr);
        if (h) { g_watchdog_handle = h; }
    }
}

extern "C" __declspec(dllexport) void Nigga() {
    restore::restore_original_code();
}

extern "C" __declspec(dllexport) void ArgalVmInterp(
    const uint8_t* bytecode,
    VmContext*     ctx,
    const uint8_t* oprev,
    uint64_t       image_base)
{
    static volatile LONG s_tick = 0;
    if ((InterlockedIncrement(&s_tick) & 0x3F) == 0)
        if (!check_integrity()) tamper_detected();

    vm::ArgalVmInterp(bytecode, ctx, oprev, image_base);
}

int __stdcall DllMain(const HMODULE instance, const DWORD reason, const void* reserved) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(instance);
    init_tamper_guards();
    return TRUE;
}
