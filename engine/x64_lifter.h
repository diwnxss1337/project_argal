#pragma once
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <random>
#include <algorithm>
#include <numeric>
#include <cstring>
#include <cassert>
#include "vm_defs.h"

namespace lifter {

struct X64Insn {
    // Prefixes
    bool rex_w = false, rex_r = false, rex_x = false, rex_b = false;
    bool pfx_66 = false;  // operand-size override (16-bit ops)
    bool pfx_67 = false;  // address-size override
    bool pfx_f2 = false;  // REPNZ/SSE
    bool pfx_f3 = false;  // REP/SSE
    bool pfx_lock = false;
    uint8_t seg_pfx = 0;  // 0=none, or 0x64/0x65

    // Opcode
    uint8_t  opcode[3] = {};
    int      opcode_len = 0; // 1, 2, or 3

    // ModRM
    bool    has_modrm = false;
    uint8_t modrm = 0;
    uint8_t mod_f = 0, reg_f = 0, rm_f = 0; // decoded fields

    // SIB
    bool    has_sib = false;
    uint8_t sib = 0;
    uint8_t sib_scale = 0, sib_index = 0, sib_base = 0;

    // Displacement
    int     disp_size = 0; // 0,1,4
    int32_t disp = 0;

    // Immediate
    int     imm_size = 0;  // 0,1,2,4,8
    int64_t imm = 0;

    // Instruction address and total length
    uint64_t rip = 0;   // address of first byte
    int      length = 0;

    // Effective operand size in bits (8/16/32/64)
    int opsz = 32;
    // Effective address size in bits
    int addrsz = 64;

    // Helpers
    // Register IDs in VmReg encoding (accounting for REX.R / REX.B)
    uint8_t reg_id() const { return (rex_r ? 8 : 0) | reg_f; }
    uint8_t rm_id()  const { return (rex_b ? 8 : 0) | rm_f;  }
    uint8_t sib_base_id()  const { return (rex_b ? 8 : 0) | sib_base; }
    uint8_t sib_index_id() const { return (rex_x ? 8 : 0) | sib_index; }
};

class X64Decoder {
public:
    static bool decode(const uint8_t* code, size_t code_size, size_t offset,
                       uint64_t rip_base, X64Insn& out) {
        const uint8_t* p = code + offset;
        const uint8_t* end = code + code_size;
        const uint8_t* start = p;
        out = {};
        out.rip = rip_base + offset;

        if (p >= end) return false;

        // ---- 1. Legacy prefixes ----
        bool done_pfx = false;
        while (!done_pfx && p < end) {
            switch (*p) {
            case 0xF0: out.pfx_lock = true; ++p; break;
            case 0xF2: out.pfx_f2 = true;   ++p; break;
            case 0xF3: out.pfx_f3 = true;   ++p; break;
            case 0x66: out.pfx_66 = true;   ++p; break;
            case 0x67: out.pfx_67 = true;   ++p; break;
            case 0x2E: case 0x3E: case 0x26:
            case 0x64: case 0x65: case 0x36:
                out.seg_pfx = *p;            ++p; break;
            default: done_pfx = true; break;
            }
        }
        if (p >= end) return false;

        // ---- 2. REX prefix (40-4F) ----
        if ((*p & 0xF0) == 0x40) {
            uint8_t rex = *p++;
            out.rex_w = (rex >> 3) & 1;
            out.rex_r = (rex >> 2) & 1;
            out.rex_x = (rex >> 1) & 1;
            out.rex_b = (rex >> 0) & 1;
        }
        if (p >= end) return false;

        // ---- 3. Effective operand size ----
        if (out.rex_w)      out.opsz = 64;
        else if (out.pfx_66) out.opsz = 16;
        else                out.opsz = 32;

        out.addrsz = out.pfx_67 ? 32 : 64;

        // ---- 4. Opcode ----
        if (*p == 0x0F) {
            out.opcode[0] = *p++;
            if (p >= end) return false;
            if (*p == 0x38 || *p == 0x3A) {
                out.opcode[1] = *p++;
                if (p >= end) return false;
                out.opcode[2] = *p++;
                out.opcode_len = 3;
            } else {
                out.opcode[1] = *p++;
                out.opcode_len = 2;
            }
        } else {
            out.opcode[0] = *p++;
            out.opcode_len = 1;
        }

        // ---- 5. ModRM + SIB + displacement ----
        if (needs_modrm(out)) {
            if (p >= end) return false;
            out.has_modrm = true;
            out.modrm = *p++;
            out.mod_f = (out.modrm >> 6) & 3;
            out.reg_f = (out.modrm >> 3) & 7;
            out.rm_f  = out.modrm & 7;

            if (out.mod_f != 3) {
                // Memory operand — may have SIB
                if (out.rm_f == 4) {
                    if (p >= end) return false;
                    out.has_sib = true;
                    out.sib = *p++;
                    out.sib_scale = (out.sib >> 6) & 3;
                    out.sib_index = (out.sib >> 3) & 7;
                    out.sib_base  = out.sib & 7;
                }
                // Displacement
                if (out.mod_f == 1) {
                    if (p >= end) return false;
                    out.disp_size = 1;
                    out.disp = (int8_t)*p++;
                } else if (out.mod_f == 2) {
                    if (p + 3 >= end) return false;
                    out.disp_size = 4;
                    uint32_t d; memcpy(&d, p, 4); p += 4;
                    out.disp = (int32_t)d;
                } else if (out.mod_f == 0 && out.rm_f == 5) {
                    // RIP-relative or disp32 (mod=0, rm=5)
                    if (p + 3 >= end) return false;
                    out.disp_size = 4;
                    uint32_t d; memcpy(&d, p, 4); p += 4;
                    out.disp = (int32_t)d;
                }
            }
        }

        // ---- 6. Immediate ----
        int isz = imm_size(out);
        if (isz > 0) {
            if (p + isz > end) return false;
            switch (isz) {
            case 1: out.imm = (int8_t)*p; break;
            case 2: { int16_t v; memcpy(&v, p, 2); out.imm = v; } break;
            case 4: { int32_t v; memcpy(&v, p, 4); out.imm = v; } break;
            case 8: { int64_t v; memcpy(&v, p, 8); out.imm = v; } break;
            }
            p += isz;
            out.imm_size = isz;
        }

        out.length = (int)(p - start);
        return out.length > 0;
    }

private:
    static bool needs_modrm(const X64Insn& i) {
        // Single-byte opcodes that have ModRM
        if (i.opcode_len == 1) {
            uint8_t op = i.opcode[0];
            // Group 1 (80-83), TEST/XCHG (84-87), MOV (88-8F), LEA (8D),
            // PUSH/POP mem (8F, FF), shift grp (C0/C1/D0-D3),
            // F6/F7 (unary), FE/FF (inc/dec/call/jmp/push),
            // ALU 00-3B (even bytes), MOV C6/C7
            if ((op >= 0x00 && op <= 0x3B && (op & 0xFE) != 0xA0) &&
                (op & 7) <= 5) return (op & 4) == 0 || (op & 6) == 0;
            // Simpler: list the ranges that definitely have ModRM
            if (op >= 0x00 && op <= 0x03) return true; // ADD
            if (op >= 0x08 && op <= 0x0B) return true; // OR
            if (op >= 0x10 && op <= 0x13) return true; // ADC
            if (op >= 0x18 && op <= 0x1B) return true; // SBB
            if (op >= 0x20 && op <= 0x23) return true; // AND
            if (op >= 0x28 && op <= 0x2B) return true; // SUB
            if (op >= 0x30 && op <= 0x33) return true; // XOR
            if (op >= 0x38 && op <= 0x3B) return true; // CMP
            if (op >= 0x80 && op <= 0x83) return true; // GRP1 imm
            if (op == 0x84 || op == 0x85) return true; // TEST
            if (op == 0x86 || op == 0x87) return true; // XCHG
            if (op >= 0x88 && op <= 0x8E) return true; // MOV
            if (op == 0x8D) return true; // LEA
            if (op == 0x8F) return true; // POP r/m
            if (op == 0xC0 || op == 0xC1) return true; // shift imm
            if (op == 0xC6 || op == 0xC7) return true; // MOV r/m,imm
            if (op >= 0xD0 && op <= 0xD3) return true; // shift 1/CL
            if (op == 0xF6 || op == 0xF7) return true; // GRP3
            if (op == 0xFE || op == 0xFF) return true; // GRP4/5
            if (op == 0x63) return true; // MOVSXD
            if (op == 0x69 || op == 0x6B) return true; // IMUL r,r/m,imm
            return false;
        }
        if (i.opcode_len == 2) {
            uint8_t op2 = i.opcode[1];
            // 0F xx opcodes with ModRM
            if (op2 >= 0x10 && op2 <= 0x17) return true; // SSE mov
            if (op2 >= 0x28 && op2 <= 0x2F) return true; // SSE
            if (op2 >= 0x40 && op2 <= 0x4F) return true; // CMOVcc
            if (op2 == 0xAF) return true; // IMUL
            if (op2 >= 0x90 && op2 <= 0x9F) return true; // SETcc
            if (op2 >= 0xB6 && op2 <= 0xBF) return true; // MOVZX/MOVSX
            if (op2 == 0xB8) return true; // POPCNT
            if (op2 == 0x1F) return true; // NOP (multi-byte)
            if (op2 == 0x44) return true; // CMOVE
            if (op2 == 0x99) return false; // SETL has no modrm? actually 0F 99 = SETE... let decoder handle
            return false;
        }
        return false;
    }

    static int imm_size(const X64Insn& i) {
        if (i.opcode_len == 1) {
            uint8_t op = i.opcode[0];
            // Immediate forms
            if (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
                op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C)
                return 1; // ALU AL, imm8
            if (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
                op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D)
                return (i.opsz == 16) ? 2 : 4; // ALU rAX, imm16/32
            if (op >= 0x40 && op <= 0x4F) return 0; // REX (consumed already)
            if (op == 0x6A) return 1; // PUSH imm8
            if (op == 0x68) return (i.pfx_66 ? 2 : 4); // PUSH imm16/32
            if (op == 0x69) return (i.opsz == 16 ? 2 : 4); // IMUL r,r/m,imm16/32
            if (op == 0x6B) return 1; // IMUL r,r/m,imm8
            if (op >= 0x70 && op <= 0x7F) return 1; // Jcc rel8
            if (op >= 0x80 && op <= 0x83) {
                if (op == 0x81) return (i.opsz == 16 ? 2 : 4);
                return 1; // 0x80, 0x82, 0x83
            }
            if (op == 0xA8) return 1; // TEST AL,imm8
            if (op == 0xA9) return (i.opsz == 16 ? 2 : 4); // TEST rAX,imm
            if (op >= 0xB0 && op <= 0xB7) return 1; // MOV r8,imm8
            if (op >= 0xB8 && op <= 0xBF) {
                if (i.rex_w) return 8;
                return (i.opsz == 16 ? 2 : 4);
            }
            if (op == 0xC0 || op == 0xC1) return 1; // shift imm8
            if (op == 0xC2) return 2; // RET imm16
            if (op == 0xC6) return 1; // MOV r/m8, imm8
            if (op == 0xC7) return (i.opsz == 16 ? 2 : 4);
            if (op == 0xCA) return 2; // RETF imm16
            if (op == 0xD0 || op == 0xD1 || op == 0xD2 || op == 0xD3) return 0;
            if (op == 0xE0 || op == 0xE1 || op == 0xE2) return 1; // LOOPNE/LOOPE/LOOP
            if (op == 0xE3) return 1; // JRCXZ
            if (op == 0xE8 || op == 0xE9) return 4; // CALL/JMP rel32
            if (op == 0xEB) return 1; // JMP rel8
            if (op == 0xF6) {
                // /0=TEST imm8, /1=TEST imm8, rest no imm
                return (i.reg_f <= 1) ? 1 : 0;
            }
            if (op == 0xF7) {
                return (i.reg_f <= 1) ? (i.opsz == 16 ? 2 : 4) : 0;
            }
            return 0;
        }
        if (i.opcode_len == 2) {
            uint8_t op2 = i.opcode[1];
            if (op2 >= 0x70 && op2 <= 0x8F) return 4; // Jcc rel32
            if (op2 >= 0xC2 && op2 <= 0xC6) return 1; // SSE with imm8 (approx)
            return 0;
        }
        return 0;
    }
};

class BytecodeEmitter {
public:
    std::vector<uint8_t> code;
    const uint8_t* opmap; // opcode_map[VmOp] -> encoded byte

    explicit BytecodeEmitter(const uint8_t* om) : opmap(om) {}

    void emit(VmOp op) { code.push_back(opmap[op]); }
    void emit_u8(uint8_t v) { code.push_back(v); }
    void emit_u16(uint16_t v) {
        code.push_back(v & 0xFF);
        code.push_back((v >> 8) & 0xFF);
    }
    void emit_i32(int32_t v) {
        uint32_t u = (uint32_t)v;
        code.push_back(u & 0xFF);
        code.push_back((u >> 8) & 0xFF);
        code.push_back((u >> 16) & 0xFF);
        code.push_back((u >> 24) & 0xFF);
    }
    void emit_u32(uint32_t v) {
        code.push_back(v & 0xFF);
        code.push_back((v >> 8) & 0xFF);
        code.push_back((v >> 16) & 0xFF);
        code.push_back((v >> 24) & 0xFF);
    }
    void emit_u64(uint64_t v) {
        for (int i = 0; i < 8; ++i)
            code.push_back((v >> (i*8)) & 0xFF);
    }
    void emit_reg(uint8_t reg) { code.push_back(reg); }

    // Patch a 4-byte offset at position `pos` in the bytecode
    void patch_i32(size_t pos, int32_t v) {
        uint32_t u = (uint32_t)v;
        code[pos]   = u & 0xFF;
        code[pos+1] = (u >> 8) & 0xFF;
        code[pos+2] = (u >> 16) & 0xFF;
        code[pos+3] = (u >> 24) & 0xFF;
    }

    // Current bytecode position
    size_t pos() const { return code.size(); }
};

// ============================================================================
// Build opcode map from a random seed (Fisher-Yates on [0..127])
// ============================================================================
inline void build_opcode_map(const uint8_t seed[32], uint8_t opmap_out[128], uint8_t revmap_out[256]) {
    // Start with identity
    uint8_t perm[128];
    for (int i = 0; i < 128; ++i) perm[i] = (uint8_t)i;

    // Seed a simple PRNG from seed bytes
    uint64_t state = 0;
    for (int i = 0; i < 32; ++i)
        state = state * 6364136223846793005ULL + seed[i] + 1;

    // Fisher-Yates shuffle
    for (int i = 127; i > 0; --i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        int j = (int)((state >> 33) % (i + 1));
        std::swap(perm[i], perm[j]);
    }

    memcpy(opmap_out, perm, 128);

    // Build reverse map
    memset(revmap_out, 0xFF, 256);
    for (int i = 0; i < 128; ++i)
        revmap_out[perm[i]] = (uint8_t)i;
}

// ============================================================================
// Resolve ModRM memory operand: returns (base_reg, disp, is_rip_relative)
// For SIB with index: returns base with disp encoding (simplified — SIB
// instructions with non-trivial index fall back to NATIVE).
// ============================================================================
struct MemRef {
    uint8_t base_reg;      // VmReg for base
    int32_t disp;
    bool    rip_relative;  // true => base is irrelevant; effective_addr = rip+next+disp
    bool    complex_sib;   // true => cannot simplify, fall back to NATIVE
    uint64_t rip_abs;      // resolved absolute address if rip_relative
};

static MemRef decode_memref(const X64Insn& i) {
    MemRef m{};
    m.disp = i.disp;

    if (i.mod_f == 0 && i.rm_f == 5 && !i.has_sib) {
        // RIP-relative
        m.rip_relative = true;
        // effective address = rip + length + disp
        m.rip_abs = i.rip + i.length + i.disp;
        return m;
    }

    if (!i.has_sib) {
        m.base_reg = i.rm_id();
        return m;
    }

    // SIB
    uint8_t base  = i.sib_base_id();
    uint8_t index = i.sib_index_id();
    uint8_t scale = i.sib_scale;

    // sib_index==4 (RSP with rex.x=0) means no index
    bool no_index = (i.sib_index == 4 && !i.rex_x);

    // Special case: base==5 mod==0 → no base (disp32 only)
    if (i.sib_base == 5 && i.mod_f == 0) {
        if (no_index) {
            // [disp32] absolute
            m.base_reg = VR_RSP; // we'll encode as RSP+disp but that's wrong
            m.complex_sib = true; // use NATIVE
            return m;
        }
        m.complex_sib = true;
        return m;
    }

    if (!no_index || scale != 0) {
        // index*scale present — complex, fall back to NATIVE
        if (!no_index) {
            m.complex_sib = true;
            return m;
        }
    }

    m.base_reg = base;
    return m;
}
static bool lift_insn(const X64Insn& i, BytecodeEmitter& e, const uint8_t* raw,
                      uint64_t image_base) {
    uint8_t op = i.opcode[0];
    int opsz = i.opsz;
    auto emit_memref = [&](const MemRef& m) {
        if (m.rip_relative) {
            e.emit_reg(0xFE);
            e.emit_u32((uint32_t)(m.rip_abs - image_base));
        } else {
            e.emit_reg(m.base_reg);
            e.emit_i32(m.disp);
        }
    };
    auto emit_movRM = [&](uint8_t dst, const MemRef& m) {
        VmOp vop;
        if (opsz == 64) vop = VMOP_MOV_RM64;
        else if (opsz == 32) vop = VMOP_MOV_RM32;
        else if (opsz == 16) vop = VMOP_MOV_RM16;
        else vop = VMOP_MOV_RM8;
        e.emit(vop);
        e.emit_reg(dst);
        emit_memref(m);
    };
    auto emit_movMR = [&](const MemRef& m, uint8_t src) {
        VmOp vop;
        if (opsz == 64) vop = VMOP_MOV_MR64;
        else if (opsz == 32) vop = VMOP_MOV_MR32;
        else if (opsz == 16) vop = VMOP_MOV_MR16;
        else vop = VMOP_MOV_MR8;
        e.emit(vop);
        emit_memref(m);
        e.emit_reg(src);
    };

    // ---- NOP variants ----
    if (op == 0x90 && !i.rex_w) { e.emit(VMOP_NOP); return true; }
    if (i.opcode_len == 2 && i.opcode[1] == 0x1F) { e.emit(VMOP_NOP); return true; }

    // ---- PUSH r64 ----
    if (op >= 0x50 && op <= 0x57 && i.opcode_len == 1) {
        uint8_t r = (uint8_t)((op & 7) | (i.rex_b ? 8 : 0));
        e.emit(VMOP_PUSH_R); e.emit_reg(r);
        return true;
    }
    // ---- POP r64 ----
    if (op >= 0x58 && op <= 0x5F && i.opcode_len == 1) {
        uint8_t r = (uint8_t)((op & 7) | (i.rex_b ? 8 : 0));
        e.emit(VMOP_POP_R); e.emit_reg(r);
        return true;
    }

    // ---- PUSH imm ----
    if (op == 0x68) { e.emit(VMOP_PUSH_I32); e.emit_i32((int32_t)i.imm); return true; }
    if (op == 0x6A) { e.emit(VMOP_PUSH_I8);  e.emit_u8((uint8_t)(int8_t)i.imm); return true; }

    // ---- POP r/m ----
    if (op == 0x8F && i.reg_f == 0 && i.mod_f == 3) {
        e.emit(VMOP_POP_R); e.emit_reg(i.rm_id()); return true;
    }

    // ---- MOV r/m, r  (88/89) ----
    if ((op == 0x88 || op == 0x89) && i.has_modrm) {
        if (op == 0x88) { const_cast<X64Insn&>(i).opsz = 8; }
        if (i.mod_f == 3) {
            // MOV rm_reg, reg_reg
            uint8_t dst = i.rm_id(), src = i.reg_id();
            if (opsz == 8) { // 8-bit: only low byte matters
                return false;
            }
            e.emit(VMOP_MOV_RR); e.emit_reg(dst); e.emit_reg(src);
            return true;
        } else {
            MemRef m = decode_memref(i);
            if (m.complex_sib) return false;
            emit_movMR(m, i.reg_id());
            return true;
        }
    }
    // ---- MOV r, r/m  (8A/8B) ----
    if ((op == 0x8A || op == 0x8B) && i.has_modrm) {
        if (op == 0x8A) { const_cast<X64Insn&>(i).opsz = 8; }
        if (i.mod_f == 3) {
            if (opsz == 8) {
                // 8-bit reg-to-reg: mov al, cl  etc.
                // Implement as:  AND dst, ~0xFF;  MOVZX_RR8 scratch... but we
                // have no scratch.  Use a two-step: clear low byte of dst,
                // then OR in the zero-extended low byte of src.
                //   AND dst, 0xFFFFFFFFFFFFFF00
                //   AND src_copy (we need src unchanged!) — can't clobber src
                // Simplest correct approach without a temp: fall to NATIVE.
                // exec_native handles 8A/8B reg correctly (loads all GPRs,
                // executes, saves all GPRs, correct low-byte semantics).
                return false;
            }
            e.emit(VMOP_MOV_RR); e.emit_reg(i.reg_id()); e.emit_reg(i.rm_id());
            return true;
        } else {
            MemRef m = decode_memref(i);
            if (m.complex_sib) return false;
            emit_movRM(i.reg_id(), m);
            return true;
        }
    }

    // ---- MOV r/m, imm  (C6/C7) ----
    if (op == 0xC6 && i.has_modrm && i.reg_f == 0) {
        if (i.mod_f == 3) return false; // MOV r8, imm8 - fall back
        MemRef m = decode_memref(i);
        if (m.complex_sib) return false;
        e.emit(VMOP_MOV_MI8);
        emit_memref(m);
        e.emit_u8((uint8_t)i.imm);
        return true;
    }
    if (op == 0xC7 && i.has_modrm && i.reg_f == 0) {
        if (i.mod_f == 3) {
            // MOV r64/32, imm32 (sign-extended for 64-bit)
            e.emit(VMOP_MOV_RI32); e.emit_reg(i.rm_id()); e.emit_i32((int32_t)i.imm);
            return true;
        }
        MemRef m = decode_memref(i);
        if (m.complex_sib) return false;
        e.emit(VMOP_MOV_MI32);
        emit_memref(m);
        e.emit_i32((int32_t)i.imm);
        return true;
    }

    // ---- MOV r, imm  (B0-BF) ----
    if (op >= 0xB0 && op <= 0xB7) {
        // Without any REX prefix, B4-B7 encode AH/CH/DH/BH (bits 8-15 of the
        // register) — these high-byte aliases cannot be expressed in the VM's
        // 64-bit register model, so fall through to NATIVE.
        bool has_rex = i.rex_w || i.rex_r || i.rex_x || i.rex_b;
        if (!has_rex && (op & 7u) >= 4u) return false; // AH/CH/DH/BH

        uint8_t vreg = static_cast<uint8_t>((op & 7u) | (i.rex_b ? 8u : 0u));

        // Implement  mov r8, imm8  as:
        //   AND vreg, 0xFFFFFFFFFFFFFF00   (clears low 8 bits, sign-extend -256)
        //   XOR vreg, (imm8 & 0xFF)        (sets low 8 bits; imm is 0..255 as
        //                                   positive i32 so sign-extend is safe)
        //
        // The XOR_RI32 sign-extends its i32 operand to 64-bit.  For any value in
        // 0x00..0xFF, the i32 is 0x000000xx (<0x80000000) so the 64-bit result
        // has zeros in bits 8-63, meaning only the low byte changes.  After the
        // AND zeroed those bits, XOR correctly OR-in the new byte value.
        const int32_t mask_clear_low8 = -256; // 0xFFFFFF00, sign-extends to ...FF00
        const int32_t byte_val = static_cast<int32_t>(
            static_cast<uint32_t>(static_cast<uint8_t>(i.imm & 0xFF)));

        e.emit(VMOP_AND_RI32); e.emit_reg(vreg); e.emit_i32(mask_clear_low8);
        e.emit(VMOP_XOR_RI32); e.emit_reg(vreg); e.emit_i32(byte_val);
        return true;
    }
    if (op >= 0xB8 && op <= 0xBF) {
        uint8_t r = (uint8_t)((op & 7) | (i.rex_b ? 8 : 0));
        if (opsz == 64) { e.emit(VMOP_MOV_RI64); e.emit_reg(r); e.emit_u64((uint64_t)i.imm); }
        else            { e.emit(VMOP_MOV_RI32); e.emit_reg(r); e.emit_i32((int32_t)i.imm); }
        return true;
    }

    // ---- MOVSXD r64, r/m32  (0x63 with REX.W) ----
    if (op == 0x63 && i.rex_w && i.has_modrm) {
        if (i.mod_f == 3) {
            e.emit(VMOP_MOVSX_RR32); e.emit_reg(i.reg_id()); e.emit_reg(i.rm_id());
            return true;
        }
        MemRef m = decode_memref(i);
        if (m.complex_sib) return false;
        e.emit(VMOP_MOVSX_RM32); e.emit_reg(i.reg_id());
        emit_memref(m);
        return true;
    }

    // ---- LEA r, m ----
    if (op == 0x8D && i.has_modrm) {
        MemRef m = decode_memref(i);
        if (m.rip_relative) {
            // VMOP_LEA_ABS stores u32 RVA; interpreter adds runtime image_base.
            e.emit(VMOP_LEA_ABS); e.emit_reg(i.reg_id());
            e.emit_u32((uint32_t)(m.rip_abs - image_base));
            return true;
        }
        if (m.complex_sib) return false;
        if (i.has_sib) {
            // Encode full LEA [base + index*scale + disp]
            e.emit(VMOP_LEA);
            e.emit_reg(i.reg_id());
            e.emit_reg(i.sib_base_id());
            bool no_index = (i.sib_index == 4 && !i.rex_x);
            e.emit_reg(no_index ? 0xFF : i.sib_index_id());
            e.emit_u8(i.sib_scale);
            e.emit_i32(m.disp);
        } else {
            e.emit(VMOP_LEA);
            e.emit_reg(i.reg_id());
            e.emit_reg(m.base_reg);
            e.emit_reg(0xFF); // no index
            e.emit_u8(0);
            e.emit_i32(m.disp);
        }
        return true;
    }

    // ---- ALU group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP (00-3B) ----
    static const VmOp alu_rr_op[8] = {
        VMOP_ADD_RR, VMOP_OR_RR,  VMOP_ADC_RR, VMOP_SBB_RR,
        VMOP_AND_RR, VMOP_SUB_RR, VMOP_XOR_RR, VMOP_CMP_RR
    };
    if (op <= 0x3B && i.has_modrm) {
        uint8_t grp = (op >> 3) & 7;
        VmOp vop = alu_rr_op[grp];
        bool rm_is_dst = !(op & 2); // direction bit: 0=rm/dst reg/src, 2=reg/dst rm/src
        uint8_t dst = rm_is_dst ? i.rm_id() : i.reg_id();
        uint8_t src = rm_is_dst ? i.reg_id() : i.rm_id();

        // 8-bit forms (op & 1 == 0) fall through to NATIVE — exec_native handles
        // the low-byte semantics correctly after the RSP-swap fix.
        if (opsz != 64 && opsz != 32) return false;

        if (i.mod_f == 3) {
            // Pure register-register ALU: simple and fast path.
            e.emit(vop); e.emit_reg(dst); e.emit_reg(src);
            return true;
        }

        // Memory operand.  Strategy: lift as load → ALU_RR → store.
        // For instructions where rm is the SOURCE (op&2 == 2, e.g. add r,m):
        //   tmp_reg = load(mem); alu dst_reg, tmp_reg
        // For instructions where rm is the DESTINATION (op&2 == 0, e.g. add m,r):
        //   tmp_reg = load(mem); alu tmp_reg, src_reg; store(mem, tmp_reg)
        // CMP always reads rm — never writes back.
        //
        // We need a scratch register that is not already used as dst or src.
        // We pick R11 (VR_R11=11) as scratch; if either operand already uses R11
        // we fall to NATIVE to avoid clobbering it.
        //
        // Complex SIB or 8-bit operand size → NATIVE (exec_native handles those).
        MemRef m = decode_memref(i);
        if (m.complex_sib) return false;

        static constexpr uint8_t k_scratch = VR_R11;
        if (dst == k_scratch || src == k_scratch) return false; // scratch collision

        // Determine which size variant of the load/store opcode to use.
        VmOp load_op  = (opsz == 64) ? VMOP_MOV_RM64 : VMOP_MOV_RM32;
        VmOp store_op = (opsz == 64) ? VMOP_MOV_MR64 : VMOP_MOV_MR32;

        if (rm_is_dst) {
            // add [mem], reg  →  scratch = load(mem); alu scratch, reg; store(mem, scratch)
            // Exception: CMP — no writeback needed.
            e.emit(load_op); e.emit_reg(k_scratch); emit_memref(m);
            e.emit(vop);     e.emit_reg(k_scratch); e.emit_reg(src);
            if (vop != VMOP_CMP_RR && vop != VMOP_TEST_RR) {
                e.emit(store_op); emit_memref(m); e.emit_reg(k_scratch);
            }
        } else {
            // add reg, [mem]  →  scratch = load(mem); alu dst_reg, scratch
            e.emit(load_op); e.emit_reg(k_scratch); emit_memref(m);
            e.emit(vop);     e.emit_reg(dst);        e.emit_reg(k_scratch);
        }
        return true;
    }
    // GRP1 immediate (80-83)
    static const VmOp alu_ri32_op[8] = {
        VMOP_ADD_RI32, VMOP_OR_RI32,  VMOP_ADC_RI32, VMOP_SBB_RI32,
        VMOP_AND_RI32, VMOP_SUB_RI32, VMOP_XOR_RI32, VMOP_CMP_RI32
    };
    static const VmOp alu_ri8_op[8] = {
        VMOP_ADD_RI8, VMOP_OR_RI8,  VMOP_ADC_RI8, VMOP_SBB_RI8,
        VMOP_AND_RI8, VMOP_SUB_RI8, VMOP_XOR_RI8, VMOP_CMP_RI8
    };
    if ((op >= 0x80 && op <= 0x83) && i.has_modrm) {
        if (opsz != 64 && opsz != 32 && op != 0x80) return false; // 8-bit → NATIVE

        VmOp vop8  = alu_ri8_op[i.reg_f];
        VmOp vop32 = alu_ri32_op[i.reg_f];
        bool is_cmp_or_test = (i.reg_f == 7); // CMP — no writeback

        if (i.mod_f == 3) {
            // Register operand — straightforward.
            if (op == 0x81) {
                e.emit(vop32); e.emit_reg(i.rm_id()); e.emit_i32((int32_t)i.imm);
            } else {
                e.emit(vop8); e.emit_reg(i.rm_id()); e.emit_u8((uint8_t)(int8_t)i.imm);
            }
            return true;
        }

        // Memory operand: load → ALU_imm → (optional) store back.
        MemRef m = decode_memref(i);
        if (m.complex_sib) return false;

        static constexpr uint8_t k_scratch = VR_R11;
        if (i.rm_id() == k_scratch) return false;

        VmOp load_op  = (opsz == 64) ? VMOP_MOV_RM64 : VMOP_MOV_RM32;
        VmOp store_op = (opsz == 64) ? VMOP_MOV_MR64 : VMOP_MOV_MR32;

        e.emit(load_op); e.emit_reg(k_scratch); emit_memref(m);
        if (op == 0x81) {
            e.emit(vop32); e.emit_reg(k_scratch); e.emit_i32((int32_t)i.imm);
        } else {
            e.emit(vop8); e.emit_reg(k_scratch); e.emit_u8((uint8_t)(int8_t)i.imm);
        }
        if (!is_cmp_or_test) {
            e.emit(store_op); emit_memref(m); e.emit_reg(k_scratch);
        }
        return true;
    }
    // ALU rAX, imm (05/0D/15/1D/25/2D/35/3D)
    if ((op & 7) == 5 && op <= 0x3D && (op & 0x0F) >= 4) {
        uint8_t grp = (op >> 3) & 7;
        VmOp vop = alu_ri32_op[grp];
        if (vop == (VmOp)0xFF) return false;
        e.emit(vop); e.emit_reg(VR_RAX); e.emit_i32((int32_t)i.imm);
        return true;
    }

    // ---- TEST ----
    if ((op == 0x84 || op == 0x85) && i.has_modrm && i.mod_f == 3) {
        e.emit(VMOP_TEST_RR); e.emit_reg(i.rm_id()); e.emit_reg(i.reg_id());
        return true;
    }
    if (op == 0xF7 && i.reg_f == 0 && i.mod_f == 3) {
        e.emit(VMOP_TEST_RI32); e.emit_reg(i.rm_id()); e.emit_i32((int32_t)i.imm);
        return true;
    }
    if (op == 0xA9) { e.emit(VMOP_TEST_RI32); e.emit_reg(VR_RAX); e.emit_i32((int32_t)i.imm); return true; }

    // ---- XCHG ----
    if ((op == 0x86 || op == 0x87) && i.mod_f == 3) {
        e.emit(VMOP_XCHG_RR); e.emit_reg(i.rm_id()); e.emit_reg(i.reg_id());
        return true;
    }

    // ---- NOT/NEG/MUL/IMUL/DIV/IDIV (F7) ----
    if (op == 0xF7 && i.mod_f == 3) {
        static const VmOp f7ops[8] = {
            VMOP_TEST_RI32, VMOP_TEST_RI32, VMOP_NOT_R, VMOP_NEG_R,
            VMOP_MUL_R, VMOP_IMUL_R, VMOP_DIV_R, VMOP_IDIV_R
        };
        VmOp vop = f7ops[i.reg_f];
        if (i.reg_f <= 1) return false; // TEST already handled above
        e.emit(vop);
        if (i.reg_f >= 2) e.emit_reg(i.rm_id());
        return true;
    }

    // ---- INC/DEC (FF /0, FF /1) ----
    if (op == 0xFF && i.mod_f == 3) {
        if (i.reg_f == 0) { e.emit(VMOP_INC_R); e.emit_reg(i.rm_id()); return true; }
        if (i.reg_f == 1) { e.emit(VMOP_DEC_R); e.emit_reg(i.rm_id()); return true; }
    }
    // FE (INC/DEC byte)
    if (op == 0xFE && i.mod_f == 3) return false; // 8-bit

    // ---- IMUL r, r/m  (0F AF) ----
    if (i.opcode_len == 2 && i.opcode[1] == 0xAF && i.mod_f == 3) {
        e.emit(VMOP_IMUL_RR); e.emit_reg(i.reg_id()); e.emit_reg(i.rm_id());
        return true;
    }
    // IMUL r, r/m, imm32  (0x69)
    if (op == 0x69 && i.mod_f == 3) {
        e.emit(VMOP_IMUL_RRI32); e.emit_reg(i.reg_id()); e.emit_reg(i.rm_id()); e.emit_i32((int32_t)i.imm);
        return true;
    }
    // IMUL r, r/m, imm8  (0x6B)
    if (op == 0x6B && i.mod_f == 3) {
        e.emit(VMOP_IMUL_RRI32); e.emit_reg(i.reg_id()); e.emit_reg(i.rm_id()); e.emit_i32((int32_t)(int8_t)i.imm);
        return true;
    }

    // ---- Shifts  D0-D3 / C0-C1 ----
    if ((op >= 0xC0 && op <= 0xC1) && i.mod_f == 3) {
        static const VmOp shop_ri[8] = {
            VMOP_ROL_RI, VMOP_ROR_RI, (VmOp)0xFF, (VmOp)0xFF,
            VMOP_SHL_RI, VMOP_SHR_RI, (VmOp)0xFF, VMOP_SAR_RI
        };
        VmOp vop = shop_ri[i.reg_f];
        if (vop == (VmOp)0xFF) return false;
        e.emit(vop); e.emit_reg(i.rm_id()); e.emit_u8((uint8_t)i.imm);
        return true;
    }
    if ((op == 0xD3) && i.mod_f == 3) {
        static const VmOp shop_rc[8] = {
            VMOP_SHL_RC, VMOP_SHR_RC, (VmOp)0xFF, (VmOp)0xFF,
            VMOP_SHL_RC, VMOP_SHR_RC, (VmOp)0xFF, VMOP_SAR_RC
        };
        VmOp vop = shop_rc[i.reg_f];
        if (vop == (VmOp)0xFF) return false;
        e.emit(vop); e.emit_reg(i.rm_id());
        return true;
    }

    // ---- CDQ / CQO ----
    if (op == 0x99) {
        e.emit(i.rex_w ? VMOP_CQO : VMOP_CDQ);
        return true;
    }

    // ---- JMP rel8/rel32 ----
    // NOTE: imm here is the rel offset; absolute target = rip + length + imm
    // We store the absolute bytecode-offset which is patched by the lifter.
    // We emit a placeholder (0) and the caller patches it.
    if (op == 0xEB) {  // JMP rel8
        e.emit(VMOP_JMP); e.emit_i32(0); // patched later
        return true;
    }
    if (op == 0xE9) {  // JMP rel32
        e.emit(VMOP_JMP); e.emit_i32(0);
        return true;
    }

    // ---- Jcc rel8 (70-7F) ----
    if (op >= 0x70 && op <= 0x7F) {
        static const VmOp jcc_ops[16] = {
            VMOP_JO,  VMOP_JNO, VMOP_JB,  VMOP_JAE,
            VMOP_JE,  VMOP_JNE, VMOP_JBE, VMOP_JA,
            VMOP_JS,  VMOP_JNS, VMOP_JP,  VMOP_JNP,
            VMOP_JL,  VMOP_JGE, VMOP_JLE, VMOP_JG
        };
        e.emit(jcc_ops[op & 0x0F]); e.emit_i32(0);
        return true;
    }

    // ---- Jcc rel32 (0F 80-8F) ----
    if (i.opcode_len == 2 && i.opcode[1] >= 0x80 && i.opcode[1] <= 0x8F) {
        static const VmOp jcc_ops[16] = {
            VMOP_JO,  VMOP_JNO, VMOP_JB,  VMOP_JAE,
            VMOP_JE,  VMOP_JNE, VMOP_JBE, VMOP_JA,
            VMOP_JS,  VMOP_JNS, VMOP_JP,  VMOP_JNP,
            VMOP_JL,  VMOP_JGE, VMOP_JLE, VMOP_JG
        };
        e.emit(jcc_ops[i.opcode[1] & 0x0F]); e.emit_i32(0);
        return true;
    }

    // ---- JRCXZ ----
    if (op == 0xE3) { e.emit(VMOP_JRCXZ); e.emit_i32(0); return true; }

    // ---- CALL rel32 ----
    if (op == 0xE8) {
        uint64_t target = i.rip + i.length + i.imm;
        // Store as u32 RVA; interpreter adds runtime image_base for ASLR safety.
        e.emit(VMOP_CALL_ABS); e.emit_u32((uint32_t)(target - image_base));
        return true;
    }
    // ---- CALL r/m  (FF /2) ----
    if (op == 0xFF && i.reg_f == 2 && i.mod_f == 3) {
        e.emit(VMOP_CALL_R); e.emit_reg(i.rm_id());
        return true;
    }
    // ---- CALL [rip+disp]  (FF /2, mod=0, rm=5) — RIP-relative indirect (IAT) ----
    // Raw bytes cannot be passed to exec_native: RIP changes in the trampoline buffer
    // so rip+disp would resolve to garbage.  Instead, store the IAT slot's RVA and
    // let the interpreter dereference it at runtime using the actual image_base.
    if (op == 0xFF && i.reg_f == 2 && i.mod_f == 0 && i.rm_f == 5) {
        uint64_t ptr_va  = i.rip + (uint64_t)i.length + (int64_t)i.disp;
        uint32_t ptr_rva = (uint32_t)(ptr_va - image_base);
        e.emit(VMOP_CALL_MEM_ABS); e.emit_u32(ptr_rva);
        return true;
    }
    // ---- JMP r/m  (FF /4) ----
    if (op == 0xFF && i.reg_f == 4 && i.mod_f == 3) {
        e.emit(VMOP_JMP); e.emit_i32(0); // indirect - special case, see below
        // Actually, indirect JMP via register needs special handling
        // Emit VMOP_CALL_R with a special "tail-call" semantic? For now NATIVE.
        e.code.pop_back(); e.code.pop_back(); e.code.pop_back(); e.code.pop_back(); e.code.pop_back();
        return false;
    }

    // ---- RET ----
    if (op == 0xC3) { e.emit(VMOP_RET); return true; }
    if (op == 0xC2) { e.emit(VMOP_RET_IMM); e.emit_u16((uint16_t)i.imm); return true; }

    // ---- MOVZX  (0F B6 = byte, 0F B7 = word) ----
    if (i.opcode_len == 2 && (i.opcode[1] == 0xB6 || i.opcode[1] == 0xB7)) {
        if (i.mod_f == 3) {
            VmOp vop = (i.opcode[1] == 0xB6) ? VMOP_MOVZX_RR8 : VMOP_MOVZX_RR16;
            e.emit(vop); e.emit_reg(i.reg_id()); e.emit_reg(i.rm_id());
            return true;
        }
        MemRef m = decode_memref(i);
        if (m.complex_sib) return false;
        VmOp vop = (i.opcode[1] == 0xB6) ? VMOP_MOVZX_RM8 : VMOP_MOVZX_RM16;
        e.emit(vop); e.emit_reg(i.reg_id());
        emit_memref(m);
        return true;
    }
    // ---- MOVSX  (0F BE = byte, 0F BF = word) ----
    if (i.opcode_len == 2 && (i.opcode[1] == 0xBE || i.opcode[1] == 0xBF)) {
        if (i.mod_f == 3) {
            VmOp vop = (i.opcode[1] == 0xBE) ? VMOP_MOVSX_RR8 : VMOP_MOVSX_RR16;
            e.emit(vop); e.emit_reg(i.reg_id()); e.emit_reg(i.rm_id());
            return true;
        }
        return false;
    }

    // ---- SETcc  (0F 90-9F) ----
    if (i.opcode_len == 2 && i.opcode[1] >= 0x90 && i.opcode[1] <= 0x9F && i.mod_f == 3) {
        uint8_t cond = i.opcode[1] & 0x0F;
        e.emit(VMOP_SETCC); e.emit_u8(cond); e.emit_reg(i.rm_id());
        return true;
    }

    // ---- CMOVcc  (0F 40-4F) ----
    if (i.opcode_len == 2 && i.opcode[1] >= 0x40 && i.opcode[1] <= 0x4F && i.mod_f == 3) {
        uint8_t cond = i.opcode[1] & 0x0F;
        e.emit(VMOP_CMOVCC); e.emit_u8(cond); e.emit_reg(i.reg_id()); e.emit_reg(i.rm_id());
        return true;
    }

    // ---- Everything else → NATIVE ----
    return false;
}

struct LiftResult {
    std::vector<uint8_t> bytecode;
    bool ok = false;
    int  failed_insns = 0; // number of instructions emitted as NATIVE
};

inline LiftResult lift_region(const uint8_t* code, size_t code_size,
                               uint64_t region_base_rip,
                               const uint8_t opmap[128],
                               uint64_t image_base)
{
    LiftResult res;
    BytecodeEmitter e(opmap);

    // Map from x64 byte-offset within region -> bytecode offset
    // (for patching branch targets)
    std::vector<int32_t> x64_to_bc(code_size + 1, -1); // -1 = not yet emitted

    // Pass 1: lift all instructions, record offset mapping, emit placeholder
    // offsets for branches.
    struct BranchPatch {
        size_t  bc_pos;      // position of the 4-byte offset in bytecode
        size_t  x64_target;  // byte offset within region of branch target
    };
    std::vector<BranchPatch> patches;

    size_t x64_off = 0;
    while (x64_off < code_size) {
        x64_to_bc[x64_off] = (int32_t)e.pos();

        X64Insn insn;
        bool dec_ok = X64Decoder::decode(code, code_size, x64_off,
                                          region_base_rip, insn);
        if (!dec_ok || insn.length == 0) {
            // Single byte NATIVE
            e.emit(VMOP_NATIVE);
            e.emit_u8(1);
            e.emit_u8(code[x64_off]);
            x64_off++;
            res.failed_insns++;
            continue;
        }

        size_t bc_before = e.pos();
        bool lifted = lift_insn(insn, e, code + x64_off, image_base);

        if (!lifted) {
            // NATIVE fallback — embed raw instruction bytes
            e.emit(VMOP_NATIVE);
            e.emit_u8((uint8_t)insn.length);
            for (int k = 0; k < insn.length; ++k)
                e.emit_u8(code[x64_off + k]);
            res.failed_insns++;
        } else {
            // Check if this was a branch (JMP/Jcc/JRCXZ) — need target patch
            uint8_t op = code[x64_off];
            bool is_branch = (op == 0xEB || op == 0xE9 ||
                             (op >= 0x70 && op <= 0x7F) ||
                             (insn.opcode_len == 2 && insn.opcode[1] >= 0x80 && insn.opcode[1] <= 0x8F) ||
                             op == 0xE3);
            if (is_branch && insn.imm_size > 0) {
                // Compute x64 target offset within region
                int64_t target_rip = insn.rip + insn.length + insn.imm;
                int64_t target_off = target_rip - (int64_t)region_base_rip;
                // The 4-byte patch offset is always at e.pos()-4 after we emit the branch
                size_t patch_pos = e.pos() - 4;
                if (target_off >= 0 && target_off <= (int64_t)code_size) {
                    patches.push_back({ patch_pos, (size_t)target_off });
                }
                // else: branch leaves region — leave as 0 (will jump to offset 0 in region)
            }
        }

        x64_off += insn.length;
    }
    x64_to_bc[code_size] = (int32_t)e.pos(); // sentinel for end-of-region

    // Pass 2: patch branch targets
    for (auto& bp : patches) {
        int32_t target_bc = x64_to_bc[bp.x64_target];
        if (target_bc >= 0) {
            e.patch_i32(bp.bc_pos, target_bc);
        }
    }

    res.bytecode = std::move(e.code);
    res.ok = true;
    return res;
}

// ============================================================================
// Build the VM entry stub placed in .diwnxss for a specific region.
// Fully position-independent: uses only RIP-relative LEA/CALL — no hardcoded
// absolute VAs — so the stub works correctly under ASLR.
//
// Calling convention (Microsoft x64 fastcall):
//   rcx = bytecode_ptr, rdx = &VmContext, r8 = oprev_map
//
// Parameters (all RVAs within the output PE image):
//   stub_rva         — RVA where stub[0] is placed in the section
//   bytecode_rgn_rva — RVA of this region's bytecode blob
//   revmap_rva       — RVA of VmHeader::opcode_rev in the section
//   iat_slot_rva     — RVA of the ArgalVmInterp IAT slot
//
// Stub layout (base 229 bytes + 30-80 bytes randomized junk):
//   Junk sled 0     (variable): anti-disasm patterns before context save
//   Phase 1 ( 97 bytes): sub rsp,0x90 + save 16 GPRs (randomized order) + save RFLAGS
//   Junk sled 1     (variable): anti-disasm patterns between save and call setup
//   Phase 2 (25-39+ bytes): argument LEAs in randomized order with optional
//                           mini junk between them, sub rsp,0x20,
//                           call [rip+disp_iat], add rsp,0x20
//   Junk sled 3     (variable): return path obfuscation
//   Phase 3 ( 85 bytes): restore RFLAGS + restore 15 GPRs (randomized order)
//   Junk sled 4     (variable): before the return
//   Epilogue (8 bytes): add rsp,0x90 + ret
//   INT3 padding to kVmStubSize
//
// All RIP-relative displacements computed dynamically from s.size().
// ============================================================================

// Helper: emit N bytes of junk that doesn't clobber any register state.
// Uses only flag-safe instructions (CLC, STC, CLD, NOP, CMC), push/pop
// pairs on random safe regs, and anti-disasm overlapping JMP patterns.
inline void emit_stub_junk(std::vector<uint8_t>& s, size_t count, std::mt19937& rng) {
    size_t emitted = 0;
    while (emitted < count) {
        size_t left = count - emitted;
        int choice = rng() % 10;

        if (choice == 0 && left >= 2) {
            // push/pop same reg (no-op, 2 bytes)
            uint8_t safe_regs[] = {0,1,2,3,6,7};
            uint8_t r = safe_regs[rng() % 6];
            s.push_back(0x50 + r); s.push_back(0x58 + r);
            emitted += 2;
        }
        else if (choice == 1 && left >= 3) {
            // jmp +1 with garbage byte (anti-disasm)
            s.push_back(0xEB); s.push_back(0x01);
            s.push_back(static_cast<uint8_t>(rng() & 0xFF));
            emitted += 3;
        }
        else if (choice == 2 && left >= 4) {
            // jmp +2 with 2 garbage bytes
            s.push_back(0xEB); s.push_back(0x02);
            s.push_back(static_cast<uint8_t>(rng())); s.push_back(static_cast<uint8_t>(rng()));
            emitted += 4;
        }
        else if (choice == 3 && left >= 7) {
            // opaque predicate (never-taken): xor r,r / test r,r / jnz +1 / 1 garbage byte
            uint8_t safe_regs[] = {0,1,2,3,6,7};
            uint8_t r = safe_regs[rng() % 6];
            s.push_back(0x31); s.push_back(0xC0 | ((r & 7) << 3) | (r & 7)); // xor r32,r32
            s.push_back(0x85); s.push_back(0xC0 | ((r & 7) << 3) | (r & 7)); // test r32,r32
            s.push_back(0x75); s.push_back(0x01); // jnz +1 (never taken)
            s.push_back(static_cast<uint8_t>(rng())); // dead byte
            emitted += 7;
        }
        else if (choice == 4 && left >= 5) {
            // Fake VEX prefix behind jmp+1 (confuses disasm)
            s.push_back(0xEB); s.push_back(0x03); // jmp +3
            s.push_back(0xC4); // VEX 3-byte prefix
            s.push_back(static_cast<uint8_t>(rng()) | 0xC0);
            s.push_back(static_cast<uint8_t>(rng()));
            emitted += 5;
        }
        else if (choice == 5 && left >= 4) {
            // UD2 behind a jmp (never executed, confuses analysis)
            s.push_back(0xEB); s.push_back(0x02); // jmp +2
            s.push_back(0x0F); s.push_back(0x0B); // UD2
            emitted += 4;
        }
        else if (choice == 6 && left >= 3) {
            // LOCK prefix behind jmp+1 (invalid, confuses linear disasm)
            s.push_back(0xEB); s.push_back(0x01); // jmp +1
            s.push_back(0xF0); // LOCK
            emitted += 3;
        }
        else if (choice == 7 && left >= 5) {
            // Fake EVEX behind jmp
            s.push_back(0xEB); s.push_back(0x03); // jmp +3
            s.push_back(0x62); // EVEX prefix
            s.push_back(static_cast<uint8_t>(rng()) | 0xF0);
            s.push_back(static_cast<uint8_t>(rng()));
            emitted += 5;
        }
        else if (choice == 8 && left >= 2) {
            // XCHG reg,reg (no-op if same reg)
            uint8_t safe_regs[] = {0,1,2,3,6,7};
            uint8_t r = safe_regs[rng() % 6];
            s.push_back(0x87); s.push_back(0xC0 | (r << 3) | r);
            emitted += 2;
        }
        else {
            // Single-byte junk: NOP, CLC, STC, CLD, CMC
            uint8_t singles[] = { 0x90, 0xF8, 0xF9, 0xFC, 0xF5 };
            s.push_back(singles[rng() % 5]);
            emitted += 1;
        }
    }
}

// Max junk budget injected into the stub
static constexpr size_t kVmStubMaxJunk = 80;
// Base stub: Phase1(97) + Phase2(39) + Phase3(93) = 229
// With junk: 229 + up to kVmStubMaxJunk, padded to fixed size
static constexpr size_t kVmStubSize = 229 + kVmStubMaxJunk;

inline std::vector<uint8_t> build_vm_entry_stub(
    uint32_t stub_rva,
    uint32_t bytecode_rgn_rva,
    uint32_t revmap_rva,
    uint32_t iat_slot_rva,
    std::mt19937& rng)
{
    std::vector<uint8_t> s;
    s.reserve(kVmStubSize);

    // Decide junk sizes for 5 insertion points.
    uint32_t total_junk = 30 + (rng() % (kVmStubMaxJunk - 30 + 1));
    uint32_t junk_slots[5];
    {
        uint32_t remaining = total_junk;
        for (int i = 0; i < 4; i++) {
            junk_slots[i] = (remaining > 4) ? (2 + rng() % (remaining / 2)) : (remaining > 0 ? 1 : 0);
            if (junk_slots[i] > remaining) junk_slots[i] = remaining;
            remaining -= junk_slots[i];
        }
        junk_slots[4] = remaining;
    }

    // === Junk sled 0: before Phase 1 ===
    emit_stub_junk(s, junk_slots[0], rng);

    // ----------------------------------------------------------------
    // Phase 1 — save context (97 bytes)
    // ----------------------------------------------------------------

    // sub rsp, 0x90  (7 bytes: REX.W 81 /5 imm32)
    // IMPORTANT: must use imm32 form (0x81) because 0x90 > 0x7F.
    // The imm8 form (0x83) would sign-extend 0x90 → -112, making it
    // "sub rsp, -112" = "add rsp, 112" which corrupts the caller's frame.
    s.push_back(0x48); s.push_back(0x81); s.push_back(0xEC);
    s.push_back(0x90); s.push_back(0x00); s.push_back(0x00); s.push_back(0x00);

    // Save all 16 GPRs in RANDOMIZED order (5 bytes each x 16 = 80 bytes)
    uint8_t save_order[16];
    for (uint8_t i = 0; i < 16; i++) save_order[i] = i;
    for (int i = 15; i > 0; --i) std::swap(save_order[i], save_order[rng() % (i + 1)]);

    auto save_gpr = [&](uint8_t vreg) {
        uint8_t off   = vreg * 8;
        uint8_t modrm = 0x44 | ((vreg & 7) << 3);
        s.push_back(vreg < 8 ? 0x48 : 0x4C);
        s.push_back(0x89);
        s.push_back(modrm); s.push_back(0x24); s.push_back(off);
    };
    for (uint8_t i = 0; i < 16; ++i) save_gpr(save_order[i]);

    // Save RFLAGS -> regs[16] at [rsp+0x80]  (10 bytes)
    s.push_back(0x9C);                                              // pushfq
    s.push_back(0x58);                                              // pop rax
    s.push_back(0x48); s.push_back(0x89); s.push_back(0x84);       // mov [rsp+0x80],rax
    s.push_back(0x24); s.push_back(0x80); s.push_back(0x00);
    s.push_back(0x00); s.push_back(0x00);

    // === Junk sled 1: after context save ===
    emit_stub_junk(s, junk_slots[1], rng);

    // ----------------------------------------------------------------
    // Phase 2 — call ArgalVmInterp(rcx, rdx, r8, r9)
    // Argument LEAs in RANDOMIZED order. All RIP-relative displacements
    // computed dynamically from s.size() so they adapt to preceding junk.
    // ----------------------------------------------------------------

    int arg_order[4] = {0, 1, 2, 3};
    for (int i = 3; i > 0; --i) std::swap(arg_order[i], arg_order[rng() % (i + 1)]);

    for (int ai = 0; ai < 4; ai++) {
        // Optionally insert mini junk between argument loads
        if (ai > 0 && (rng() % 3 == 0) && junk_slots[2] > 0) {
            uint32_t mini = 1 + rng() % ((std::min)(junk_slots[2], (uint32_t)5));
            emit_stub_junk(s, mini, rng);
            junk_slots[2] -= mini;
        }

        switch (arg_order[ai]) {
        case 0: { // lea rdx, [rsp]  (4 bytes: 48 8D 14 24)
            s.push_back(0x48); s.push_back(0x8D); s.push_back(0x14); s.push_back(0x24);
            break;
        }
        case 1: { // lea r9, [rip+disp_base]  (7 bytes: 4C 8D 0D disp32)
            size_t rip_after = s.size() + 7;
            int32_t disp = -(int32_t)(stub_rva + (uint32_t)rip_after);
            uint32_t ud = (uint32_t)disp;
            s.push_back(0x4C); s.push_back(0x8D); s.push_back(0x0D);
            s.push_back(ud & 0xFF); s.push_back((ud >> 8) & 0xFF);
            s.push_back((ud >> 16) & 0xFF); s.push_back((ud >> 24) & 0xFF);
            break;
        }
        case 2: { // lea rcx, [rip+disp_bc]  (7 bytes: 48 8D 0D disp32)
            size_t rip_after = s.size() + 7;
            int32_t disp = (int32_t)((int64_t)bytecode_rgn_rva - (int64_t)(stub_rva + rip_after));
            uint32_t ud = (uint32_t)disp;
            s.push_back(0x48); s.push_back(0x8D); s.push_back(0x0D);
            s.push_back(ud & 0xFF); s.push_back((ud >> 8) & 0xFF);
            s.push_back((ud >> 16) & 0xFF); s.push_back((ud >> 24) & 0xFF);
            break;
        }
        case 3: { // lea r8, [rip+disp_rm]  (7 bytes: 4C 8D 05 disp32)
            size_t rip_after = s.size() + 7;
            int32_t disp = (int32_t)((int64_t)revmap_rva - (int64_t)(stub_rva + rip_after));
            uint32_t ud = (uint32_t)disp;
            s.push_back(0x4C); s.push_back(0x8D); s.push_back(0x05);
            s.push_back(ud & 0xFF); s.push_back((ud >> 8) & 0xFF);
            s.push_back((ud >> 16) & 0xFF); s.push_back((ud >> 24) & 0xFF);
            break;
        }
        }
    }

    // Remaining junk from slot 2
    if (junk_slots[2] > 0) emit_stub_junk(s, junk_slots[2], rng);

    // sub rsp, 0x20  (shadow space, 4 bytes)
    s.push_back(0x48); s.push_back(0x83); s.push_back(0xEC); s.push_back(0x20);

    // call [rip+disp_iat]  (6 bytes: FF 15 disp32) — dynamic offset
    {
        size_t rip_after = s.size() + 6;
        int32_t disp = (int32_t)((int64_t)iat_slot_rva - (int64_t)(stub_rva + rip_after));
        uint32_t ud = (uint32_t)disp;
        s.push_back(0xFF); s.push_back(0x15);
        s.push_back(ud & 0xFF); s.push_back((ud >> 8) & 0xFF);
        s.push_back((ud >> 16) & 0xFF); s.push_back((ud >> 24) & 0xFF);
    }

    // add rsp, 0x20  (4 bytes)
    s.push_back(0x48); s.push_back(0x83); s.push_back(0xC4); s.push_back(0x20);

    // === Junk sled 3: after the call (return path obfuscation) ===
    emit_stub_junk(s, junk_slots[3], rng);

    // ----------------------------------------------------------------
    // Phase 3 — restore context
    // ----------------------------------------------------------------

    // Restore RFLAGS from regs[16] at [rsp+0x80]  (10 bytes)
    s.push_back(0x48); s.push_back(0x8B); s.push_back(0x84);
    s.push_back(0x24); s.push_back(0x80); s.push_back(0x00);
    s.push_back(0x00); s.push_back(0x00);
    s.push_back(0x50);  // push rax
    s.push_back(0x9D);  // popfq

    // Restore 15 GPRs (skip RSP=4) in RANDOMIZED order (75 bytes)
    uint8_t restore_order[15];
    { int j = 0; for (uint8_t i = 0; i < 16; i++) { if (i != VR_RSP) restore_order[j++] = i; } }
    for (int i = 14; i > 0; --i) std::swap(restore_order[i], restore_order[rng() % (i + 1)]);

    auto restore_gpr = [&](uint8_t vreg) {
        uint8_t off   = vreg * 8;
        uint8_t modrm = 0x44 | ((vreg & 7) << 3);
        s.push_back(vreg < 8 ? 0x48 : 0x4C);
        s.push_back(0x8B);
        s.push_back(modrm); s.push_back(0x24); s.push_back(off);
    };
    for (uint8_t i = 0; i < 15; ++i) restore_gpr(restore_order[i]);

    // === Junk sled 4: before the return ===
    emit_stub_junk(s, junk_slots[4], rng);

    // add rsp, 0x90  (7 bytes: REX.W 81 C4 imm32)
    s.push_back(0x48); s.push_back(0x81); s.push_back(0xC4);
    s.push_back(0x90); s.push_back(0x00); s.push_back(0x00); s.push_back(0x00);

    // ret  (1 byte)
    s.push_back(0xC3);

    // Pad to kVmStubSize with INT3 so section layout math stays simple
    while (s.size() < kVmStubSize) s.push_back(0xCC);

    assert(s.size() <= kVmStubSize && "VM stub exceeded max size");
    return s;
}

// ============================================================================
// Build the .argal init stub (called once from the PE entry point).
//
// The stub maps payload.dll from the .argal section using the reflective
// loader, then stores the resolved function pointers into two slots in
// .diwnxss.  A lock cmpxchg once-flag prevents double-initialisation.
//
// Layout (65 bytes):
//  [0 ] xor eax,eax                           ; expected = 0 (uninitialized)
//  [2 ] mov ecx,1
//  [7 ] lock cmpxchg [rip+d_once],ecx         ; atomically claim init slot
//  [15] jnz done                               ; another thread beat us → skip
//  [21] lea rcx,[rip+d_argal]                 ; rcx = raw .argal bytes
//  [28] lea rdx,[rip+d_nigga_fn_ptr]          ; rdx = &nigga_fn_ptr (2nd arg)
//  [35] mov rax,rcx                           ; rax = argal base
//  [38] mov r8d,argal_load_foff               ; r8  = file offset of ArgalLoad
//  [44] add rax,r8                            ; rax = &ArgalLoad in raw bytes
//  [47] sub rsp,0x28
//  [51] call rax                              ; ArgalLoad(raw, &nigga_fn_ptr)
//  [53] add rsp,0x28
//  [57] mov [rip+d_vm_fn_ptr],rax            ; store ArgalVmInterp ptr
//  [64] ret
// ============================================================================
static constexpr size_t kInitStubSize = 65;

inline std::vector<uint8_t> build_argal_init_stub(
    uint32_t stub_rva,
    uint32_t once_flag_rva,
    uint32_t vm_fn_ptr_rva,
    uint32_t nigga_fn_ptr_rva,
    uint32_t argal_section_rva,
    uint32_t argal_load_foff)
{
    std::vector<uint8_t> s;
    s.reserve(kInitStubSize);

    auto p4 = [&](uint32_t v) {
        s.push_back(v & 0xFF); s.push_back((v>>8)&0xFF);
        s.push_back((v>>16)&0xFF); s.push_back((v>>24)&0xFF);
    };

    // [0] xor eax, eax  (2)
    s.push_back(0x31); s.push_back(0xC0);

    // [2] mov ecx, 1  (5)
    s.push_back(0xB9); p4(1);

    // [7] lock cmpxchg [rip+d_once], ecx  (8)
    //     RIP after = stub_rva + 15
    {
        int32_t d = (int32_t)(once_flag_rva) - (int32_t)(stub_rva + 15);
        s.push_back(0xF0); s.push_back(0x0F); s.push_back(0xB1); s.push_back(0x0D);
        p4((uint32_t)d);
    }

    // [15] jnz done  (6)  — done is at offset 64; RIP after = stub_rva+21
    {
        int32_t d = (int32_t)(stub_rva + 64) - (int32_t)(stub_rva + 21); // = 43
        s.push_back(0x0F); s.push_back(0x85); p4((uint32_t)d);
    }

    // [21] lea rcx, [rip+d_argal]  (7)
    //      RIP after = stub_rva + 28
    {
        int32_t d = (int32_t)(argal_section_rva) - (int32_t)(stub_rva + 28);
        s.push_back(0x48); s.push_back(0x8D); s.push_back(0x0D); p4((uint32_t)d);
    }

    // [28] lea rdx, [rip+d_nigga_fn_ptr]  (7)
    //      RIP after = stub_rva + 35
    {
        int32_t d = (int32_t)(nigga_fn_ptr_rva) - (int32_t)(stub_rva + 35);
        s.push_back(0x48); s.push_back(0x8D); s.push_back(0x15); p4((uint32_t)d);
    }

    // [35] mov rax, rcx  (3)
    s.push_back(0x48); s.push_back(0x89); s.push_back(0xC8);

    // [38] mov r8d, argal_load_foff  (6)  — zero-extends to r8
    s.push_back(0x41); s.push_back(0xB8); p4(argal_load_foff);

    // [44] add rax, r8  (3)   — rax = &ArgalLoad in raw .argal bytes
    s.push_back(0x4C); s.push_back(0x01); s.push_back(0xC0);

    // [47] sub rsp, 0x28  (4)
    s.push_back(0x48); s.push_back(0x83); s.push_back(0xEC); s.push_back(0x28);

    // [51] call rax  (2)
    s.push_back(0xFF); s.push_back(0xD0);

    // [53] add rsp, 0x28  (4)
    s.push_back(0x48); s.push_back(0x83); s.push_back(0xC4); s.push_back(0x28);

    // [57] mov [rip+d_vm_fn_ptr], rax  (7)
    //      RIP after = stub_rva + 64
    {
        int32_t d = (int32_t)(vm_fn_ptr_rva) - (int32_t)(stub_rva + 64);
        s.push_back(0x48); s.push_back(0x89); s.push_back(0x05); p4((uint32_t)d);
    }

    // [64] ret  (1)
    s.push_back(0xC3);

    assert(s.size() == kInitStubSize && "init stub size mismatch");
    return s;
}

static constexpr size_t kVmEpStubSize = 36;

inline std::vector<uint8_t> build_vm_ep_stub(
    uint32_t stub_rva,
    uint32_t init_stub_rva,
    uint32_t nigga_fn_ptr_rva,
    uint32_t original_ep_rva)
{
    std::vector<uint8_t> s;
    s.reserve(kVmEpStubSize);

    auto p4 = [&](uint32_t v) {
        s.push_back(v & 0xFF); s.push_back((v>>8)&0xFF);
        s.push_back((v>>16)&0xFF); s.push_back((v>>24)&0xFF);
    };

    // [0] sub rsp, 0x28  (4)
    s.push_back(0x48); s.push_back(0x83); s.push_back(0xEC); s.push_back(0x28);

    // [4] call rel32  (5)  — RIP after = stub_rva + 9
    {
        int32_t d = (int32_t)(init_stub_rva) - (int32_t)(stub_rva + 9);
        s.push_back(0xE8); p4((uint32_t)d);
    }

    // [9] add rsp, 0x28  (4)
    s.push_back(0x48); s.push_back(0x83); s.push_back(0xC4); s.push_back(0x28);

    // [13] sub rsp, 0x28  (4)
    s.push_back(0x48); s.push_back(0x83); s.push_back(0xEC); s.push_back(0x28);

    // [17] call [rip+d_nigga]  (6: FF 15 disp32)  — RIP after = stub_rva + 23
    {
        int32_t d = (int32_t)(nigga_fn_ptr_rva) - (int32_t)(stub_rva + 23);
        s.push_back(0xFF); s.push_back(0x15); p4((uint32_t)d);
    }

    // [23] add rsp, 0x28  (4)
    s.push_back(0x48); s.push_back(0x83); s.push_back(0xC4); s.push_back(0x28);

    // [27] lea rax, [rip+oep_disp]  (7)  — RIP after = stub_rva + 34
    {
        int32_t d = (int32_t)(original_ep_rva) - (int32_t)(stub_rva + 34);
        s.push_back(0x48); s.push_back(0x8D); s.push_back(0x05); p4((uint32_t)d);
    }

    // [34] jmp rax  (2)
    s.push_back(0xFF); s.push_back(0xE0);

    assert(s.size() == kVmEpStubSize && "VM EP stub size mismatch");
    return s;
}

} // namespace lifter
