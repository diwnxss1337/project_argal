#pragma once
#include <cstdint>

// ============================================================================
// VM opcode set (base values — randomized per-build via opcode_map[])
// ============================================================================
enum VmOp : uint8_t {
    // -- No operands --
    VMOP_NOP = 0,
    VMOP_RET,           // exit VM, return to caller (models x64 RET)
    VMOP_RET_IMM,       // [imm16:2] ret N (clean stack)
    VMOP_CDQ,           // sign-extend EAX -> EDX
    VMOP_CQO,           // sign-extend RAX -> RDX

    // -- Reg <- Reg  [dst:1][src:1] --
    VMOP_MOV_RR,
    VMOP_MOVZX_RR8,     // dst64 = (uint8_t)src
    VMOP_MOVZX_RR16,    // dst64 = (uint16_t)src
    VMOP_MOVSX_RR8,     // dst64 = (int8_t)src
    VMOP_MOVSX_RR16,    // dst64 = (int16_t)src
    VMOP_MOVSX_RR32,    // dst64 = (int32_t)src

    // -- Reg <- Imm  [dst:1][imm:N] --
    VMOP_MOV_RI8,       // sign-extend imm8  -> dst64
    VMOP_MOV_RI32,      // sign-extend imm32 -> dst64
    VMOP_MOV_RI64,      // full imm64        -> dst64

    // -- Reg <- Mem  [dst:1][base:1][disp32:4] --
    VMOP_MOV_RM8,       // zero-extend byte read
    VMOP_MOV_RM16,      // zero-extend word read
    VMOP_MOV_RM32,      // zero-extend dword read
    VMOP_MOV_RM64,      // qword read
    VMOP_MOVZX_RM8,
    VMOP_MOVZX_RM16,
    VMOP_MOVSX_RM8,
    VMOP_MOVSX_RM16,
    VMOP_MOVSX_RM32,

    // -- Mem <- Reg  [base:1][disp32:4][src:1] --
    VMOP_MOV_MR8,
    VMOP_MOV_MR16,
    VMOP_MOV_MR32,
    VMOP_MOV_MR64,

    // -- Mem <- Imm  [base:1][disp32:4][imm32:4] (sign-extended) --
    VMOP_MOV_MI32,
    VMOP_MOV_MI8,       // [base:1][disp32:4][imm8:1]

    // -- LEA  [dst:1][base:1][index:1][scale:1][disp32:4]
    //    index=0xFF means no index register --
    VMOP_LEA,
    // -- LEA RIP-relative (resolved to absolute at lift time)
    //    [dst:1][abs_addr:8] --
    VMOP_LEA_ABS,

    // -- Stack  [reg:1] --
    VMOP_PUSH_R,
    VMOP_POP_R,
    // -- Stack  [imm:N] --
    VMOP_PUSH_I8,       // sign-extended
    VMOP_PUSH_I32,      // sign-extended

    // -- XCHG  [r1:1][r2:1] --
    VMOP_XCHG_RR,

    // -- Arithmetic reg,reg  [dst:1][src:1] (updates RFLAGS) --
    VMOP_ADD_RR,
    VMOP_SUB_RR,
    VMOP_ADC_RR,
    VMOP_SBB_RR,
    VMOP_AND_RR,
    VMOP_OR_RR,
    VMOP_XOR_RR,
    VMOP_CMP_RR,        // sets flags only, no store
    VMOP_TEST_RR,       // sets flags only, no store
    VMOP_IMUL_RR,       // dst *= src (signed)

    // -- Arithmetic reg,imm8  [dst:1][imm8:1] --
    VMOP_ADD_RI8,
    VMOP_SUB_RI8,
    VMOP_ADC_RI8,
    VMOP_SBB_RI8,
    VMOP_AND_RI8,
    VMOP_OR_RI8,
    VMOP_XOR_RI8,
    VMOP_CMP_RI8,

    // -- Arithmetic reg,imm32  [dst:1][imm32:4] --
    VMOP_ADD_RI32,
    VMOP_SUB_RI32,
    VMOP_ADC_RI32,
    VMOP_SBB_RI32,
    VMOP_AND_RI32,
    VMOP_OR_RI32,
    VMOP_XOR_RI32,
    VMOP_CMP_RI32,
    VMOP_TEST_RI32,
    VMOP_IMUL_RRI32,    // [dst:1][src:1][imm32:4]  dst = src * imm

    // -- Unary  [dst:1] --
    VMOP_NOT_R,
    VMOP_NEG_R,
    VMOP_INC_R,
    VMOP_DEC_R,
    VMOP_MUL_R,         // RDX:RAX = RAX * src  (unsigned)
    VMOP_IMUL_R,        // RDX:RAX = RAX * src  (signed, 1-operand form)
    VMOP_DIV_R,         // RAX = RDX:RAX / src, RDX = rem  (unsigned)
    VMOP_IDIV_R,        // signed version

    // -- Shift  [dst:1][imm8:1] --
    VMOP_SHL_RI,
    VMOP_SHR_RI,
    VMOP_SAR_RI,
    VMOP_ROL_RI,
    VMOP_ROR_RI,

    // -- Shift by CL  [dst:1] --
    VMOP_SHL_RC,
    VMOP_SHR_RC,
    VMOP_SAR_RC,

    // -- Branches  [rel32:4]  (offset relative to bytecode START) --
    VMOP_JMP,
    VMOP_JE,   VMOP_JNE,
    VMOP_JL,   VMOP_JGE,
    VMOP_JLE,  VMOP_JG,
    VMOP_JB,   VMOP_JAE,
    VMOP_JBE,  VMOP_JA,
    VMOP_JS,   VMOP_JNS,
    VMOP_JO,   VMOP_JNO,
    VMOP_JP,   VMOP_JNP,
    VMOP_JRCXZ,

    // -- CALL  --
    // call absolute native address  [abs_addr:8]
    VMOP_CALL_ABS,
    // call via register  [reg:1]
    VMOP_CALL_R,
    // call through memory ptr  [rva32:4]  — target = *(image_base + rva32)
    // Used for FF/2 mod=0 rm=5 (RIP-relative indirect call — IAT pattern)
    VMOP_CALL_MEM_ABS,

    // -- SETcc  [cond:1][dst_reg:1] --
    VMOP_SETCC,

    // -- CMOVcc  [cond:1][dst:1][src:1] --
    VMOP_CMOVCC,

    // -- NATIVE passthrough (unsupported insn)
    //    [len:1][raw_bytes:len] — copied verbatim to a temp buffer and exec'd --
    VMOP_NATIVE,

    VMOP_COUNT  // must be <= 128
};

static_assert((int)VMOP_COUNT <= 128,
    "Too many VM opcodes — opcode byte space exceeded");

// Condition code indices (match x86 Jcc/SETcc/CMOVcc encoding bit[3:0])
enum VmCond : uint8_t {
    VC_O=0,  VC_NO=1, VC_B=2,  VC_AE=3,
    VC_E=4,  VC_NE=5, VC_BE=6, VC_A=7,
    VC_S=8,  VC_NS=9, VC_P=10, VC_NP=11,
    VC_L=12, VC_GE=13,VC_LE=14,VC_G=15
};

// Virtual register IDs (match x64 ModRM register encoding)
enum VmReg : uint8_t {
    VR_RAX=0, VR_RCX=1, VR_RDX=2,  VR_RBX=3,
    VR_RSP=4, VR_RBP=5, VR_RSI=6,  VR_RDI=7,
    VR_R8=8,  VR_R9=9,  VR_R10=10, VR_R11=11,
    VR_R12=12,VR_R13=13,VR_R14=14, VR_R15=15,
    VR_RFLAGS=16,
    VR_COUNT=17
};

// x86 RFLAGS bit masks
static constexpr uint64_t RFLAG_CF = (1ULL << 0);
static constexpr uint64_t RFLAG_PF = (1ULL << 2);
static constexpr uint64_t RFLAG_AF = (1ULL << 4);
static constexpr uint64_t RFLAG_ZF = (1ULL << 6);
static constexpr uint64_t RFLAG_SF = (1ULL << 7);
static constexpr uint64_t RFLAG_OF = (1ULL << 11);

// ============================================================================
// VM execution context (saved/restored around the interpreter)
// ============================================================================
#pragma pack(push, 1)
struct VmContext {
    uint64_t regs[VR_COUNT];  // regs[0..15] = RAX..R15, regs[16] = RFLAGS
};

// ============================================================================
// Per-build VM header stored in .diwnxss section (after the existing PackedHeader)
// ============================================================================
struct VmHeader {
    uint32_t magic;           // 'ARVM' = 0x4D565241
    uint8_t  opcode_map[128]; // randomized encoding: encoded_byte = opcode_map[VmOp]
    uint8_t  opcode_rev[256]; // reverse map: VmOp = opcode_rev[encoded_byte]
    uint32_t bytecode_rva;    // RVA of the bytecode blob
    uint32_t bytecode_size;
    uint32_t num_vm_regions;
    // Followed by num_vm_regions * VmRegionDesc entries
};

struct VmRegionDesc {
    uint32_t original_rva;    // where the JMP trampoline was placed
    uint32_t bytecode_offset; // offset into bytecode blob for this region
    uint32_t vm_entry_rva;    // RVA of the VM setup stub in .diwnxss
};
#pragma pack(pop)
