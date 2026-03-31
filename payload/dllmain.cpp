#include <Windows.h>
#include <cstdint>
#include <cstring>
#include "restore_opcodes.h"
#include "vm_interpreter.h"

//change here

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

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    uint16_t nsec = nt->FileHeader.NumberOfSections;

    g_nguards = 0;
    for (uint16_t i = 0; i < nsec && g_nguards < 2; ++i) {
        char name[9] = {};
        memcpy(name, sec[i].Name, 8);
        if (!strcmp(name, ".text") || !strcmp(name, ".rdata")) {
            const uint8_t* base = (const uint8_t*)hmod + sec[i].VirtualAddress;
            size_t         sz   = sec[i].Misc.VirtualSize;
            g_guards[g_nguards++] = { base, sz, crc32_buf(base, sz) };
        }
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
