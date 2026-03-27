#pragma once
// vm_interpreter.h — runtime virtual machine interpreter (payload side)
// ArgalVmInterp(bytecode, ctx, oprev) — interprets VM bytecode using
// the reverse opcode map (oprev[encoded_byte] = VmOp base value).

#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <Windows.h>
#include "vm_defs.h"

namespace vm {

struct Reader {
    const uint8_t* base;
    uint32_t       pos;
    uint8_t  u8()  { return base[pos++]; }
    uint16_t u16() { uint16_t v; memcpy(&v,base+pos,2); pos+=2; return v; }
    uint32_t u32() { uint32_t v; memcpy(&v,base+pos,4); pos+=4; return v; }
    int32_t  i32() { int32_t  v; memcpy(&v,base+pos,4); pos+=4; return v; }
    uint64_t u64() { uint64_t v; memcpy(&v,base+pos,8); pos+=8; return v; }
    uint8_t  reg() { return u8(); }
};

// Read a memory address operand from bytecode:
//   [0xFE][rva32]          -> image_base + rva32   (RIP-relative, ASLR-safe)
//   [base_reg][disp32]     -> ctx->regs[base_reg] + sign_extend(disp32)
static inline uint64_t mem_addr(Reader& r, VmContext* ctx, uint64_t image_base) {
    uint8_t base_reg = r.reg();
    if (base_reg == 0xFE) return image_base + r.u32();
    return ctx->regs[base_reg] + (int64_t)r.i32();
}

static inline uint8_t parity8(uint8_t v) {
    v ^= v>>4; v ^= v>>2; v ^= v>>1; return (~v)&1;
}
static inline void flags_logic(VmContext* ctx, uint64_t res) {
    uint64_t& f = ctx->regs[VR_RFLAGS];
    f &= ~(RFLAG_CF|RFLAG_PF|RFLAG_AF|RFLAG_ZF|RFLAG_SF|RFLAG_OF);
    if (!res)           f |= RFLAG_ZF;
    if (res>>63)        f |= RFLAG_SF;
    if (parity8((uint8_t)res)) f |= RFLAG_PF;
}
static inline void flags_add(VmContext* ctx, uint64_t a, uint64_t b, uint64_t r) {
    uint64_t& f = ctx->regs[VR_RFLAGS];
    f &= ~(RFLAG_CF|RFLAG_PF|RFLAG_AF|RFLAG_ZF|RFLAG_SF|RFLAG_OF);
    if (!r)  f |= RFLAG_ZF;
    if (r>>63) f |= RFLAG_SF;
    if (parity8((uint8_t)r)) f |= RFLAG_PF;
    if (r < a) f |= RFLAG_CF;
    if (!((a^b)>>63) && ((a^r)>>63)) f |= RFLAG_OF;
    if (((a&0xF)+(b&0xF))>0xF) f |= RFLAG_AF;
}
static inline void flags_sub(VmContext* ctx, uint64_t a, uint64_t b, uint64_t r) {
    uint64_t& f = ctx->regs[VR_RFLAGS];
    f &= ~(RFLAG_CF|RFLAG_PF|RFLAG_AF|RFLAG_ZF|RFLAG_SF|RFLAG_OF);
    if (!r)  f |= RFLAG_ZF;
    if (r>>63) f |= RFLAG_SF;
    if (parity8((uint8_t)r)) f |= RFLAG_PF;
    if (a < b) f |= RFLAG_CF;
    if (((a^b)>>63) && ((a^r)>>63)) f |= RFLAG_OF;
    if ((a&0xF)<(b&0xF)) f |= RFLAG_AF;
}

static inline void flags_adc(VmContext* ctx, uint64_t a, uint64_t b, uint64_t cf_in, uint64_t r) {
    uint64_t& f = ctx->regs[VR_RFLAGS];
    f &= ~(RFLAG_CF|RFLAG_PF|RFLAG_AF|RFLAG_ZF|RFLAG_SF|RFLAG_OF);
    if (!r) f |= RFLAG_ZF;
    if (r>>63) f |= RFLAG_SF;
    if (parity8((uint8_t)r)) f |= RFLAG_PF;
    if (r < a || (cf_in && r == a)) f |= RFLAG_CF;
    if (!((a^b)>>63) && ((a^r)>>63)) f |= RFLAG_OF;
    if (((a&0xF)+(b&0xF)+cf_in)>0xF) f |= RFLAG_AF;
}

static inline void flags_sbb(VmContext* ctx, uint64_t a, uint64_t b, uint64_t cf_in, uint64_t r) {
    uint64_t& f = ctx->regs[VR_RFLAGS];
    f &= ~(RFLAG_CF|RFLAG_PF|RFLAG_AF|RFLAG_ZF|RFLAG_SF|RFLAG_OF);
    if (!r) f |= RFLAG_ZF;
    if (r>>63) f |= RFLAG_SF;
    if (parity8((uint8_t)r)) f |= RFLAG_PF;
    uint64_t full = b + cf_in;
    if (a < full || (cf_in && b == ~0ULL)) f |= RFLAG_CF;
    if (((a^b)>>63) && ((a^r)>>63)) f |= RFLAG_OF;
    if ((a&0xF) < ((b&0xF)+cf_in)) f |= RFLAG_AF;
}

static inline bool eval_cond(uint8_t c, const VmContext* ctx) {
    uint64_t f = ctx->regs[VR_RFLAGS];
    bool CF=(f>>0)&1, PF=(f>>2)&1, ZF=(f>>6)&1, SF=(f>>7)&1, OF=(f>>11)&1;
    switch (c&15) {
    case 0:  return OF;
    case 1:  return !OF;
    case 2:  return CF;
    case 3:  return !CF;
    case 4:  return ZF;
    case 5:  return !ZF;
    case 6:  return CF||ZF;
    case 7:  return !CF&&!ZF;
    case 8:  return SF;
    case 9:  return !SF;
    case 10: return PF;
    case 11: return !PF;
    case 12: return SF!=OF;
    case 13: return SF==OF;
    case 14: return ZF||(SF!=OF);
    case 15: return !ZF&&(SF==OF);
    }
    return false;
}

static void exec_native(const uint8_t* bytes, uint8_t len, VmContext* ctx) {
    if (!len) return;
    uint8_t* buf = (uint8_t*)VirtualAlloc(nullptr, 512,
                        MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buf) return;
    uint8_t* p = buf;

    // push non-volatile registers
    *p++=0x53; *p++=0x56; *p++=0x57;
    *p++=0x41;*p++=0x54; *p++=0x41;*p++=0x55;
    *p++=0x41;*p++=0x56; *p++=0x41;*p++=0x57;

    // mov r10, ctx (imm64)
    uint64_t ctx_addr = (uint64_t)ctx;
    *p++=0x49; *p++=0xBA; memcpy(p,&ctx_addr,8); p+=8;

    // Load RFLAGS: mov rax,[r10+0x80]; push rax; popfq
    *p++=0x49;*p++=0x8B;*p++=0x82;*p++=0x80;*p++=0;*p++=0;*p++=0;
    *p++=0x50; *p++=0x9D;

    // Load all GPRs except RSP and R10
    auto load = [&](uint8_t vr) {
        uint8_t off=vr*8;
        uint8_t rex=(vr>=8)?0x4D:0x49;
        uint8_t mrm=0x42|((vr&7)<<3);  // rm=2 → R10 (REX.B extends to index 10)
        *p++=rex;*p++=0x8B;*p++=mrm;*p++=off;
    };
    for (uint8_t r2=0;r2<16;++r2) { if(r2!=VR_RSP&&r2!=VR_R10) load(r2); }

    // Emit native instruction
    memcpy(p, bytes, len); p+=len;

    // Save GPRs (except RSP and R10) back
    auto save = [&](uint8_t vr) {
        uint8_t off=vr*8;
        uint8_t rex=(vr>=8)?0x4D:0x49;
        uint8_t mrm=0x42|((vr&7)<<3);  // rm=2 → R10 (REX.B extends to index 10)
        *p++=rex;*p++=0x89;*p++=mrm;*p++=off;
    };
    for (uint8_t r2=0;r2<16;++r2) { if(r2!=VR_RSP&&r2!=VR_R10) save(r2); }

    // Save RFLAGS: pushfq; pop rax; mov [r10+0x80],rax
    *p++=0x9C;*p++=0x58;
    *p++=0x49;*p++=0x89;*p++=0x82;*p++=0x80;*p++=0;*p++=0;*p++=0;

    // pop non-volatile registers
    *p++=0x41;*p++=0x5F;*p++=0x41;*p++=0x5E;
    *p++=0x41;*p++=0x5D;*p++=0x41;*p++=0x5C;
    *p++=0x5F;*p++=0x5E;*p++=0x5B;
    *p++=0xC3;

    ((void(*)())buf)();
    VirtualFree(buf,0,MEM_RELEASE);
}

__declspec(noinline)
void ArgalVmInterp(const uint8_t* bytecode, VmContext* ctx, const uint8_t* oprev,
                   uint64_t image_base) {
    Reader r{bytecode,0};
#define MA(r,ctx) mem_addr((r),(ctx),(image_base))
    for(;;) {
        VmOp op = (VmOp)oprev[r.u8()];
        switch(op) {
        case VMOP_NOP: break;
        case VMOP_RET: return;
        case VMOP_RET_IMM: { uint16_t n=r.u16(); ctx->regs[VR_RSP]+=n; return; }
        case VMOP_CDQ: ctx->regs[VR_RDX]=(uint64_t)(int64_t)(int32_t)ctx->regs[VR_RAX]; break;
        case VMOP_CQO: ctx->regs[VR_RDX]=(ctx->regs[VR_RAX]>>63)?~0ULL:0ULL; break;

        // MOV reg<-reg
        case VMOP_MOV_RR:     { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]=ctx->regs[s]; break; }
        case VMOP_MOVZX_RR8:  { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]=(uint8_t)ctx->regs[s]; break; }
        case VMOP_MOVZX_RR16: { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]=(uint16_t)ctx->regs[s]; break; }
        case VMOP_MOVSX_RR8:  { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]=(uint64_t)(int64_t)(int8_t)ctx->regs[s]; break; }
        case VMOP_MOVSX_RR16: { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]=(uint64_t)(int64_t)(int16_t)ctx->regs[s]; break; }
        case VMOP_MOVSX_RR32: { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]=(uint64_t)(int64_t)(int32_t)ctx->regs[s]; break; }

        // MOV reg<-imm
        case VMOP_MOV_RI8:  { uint8_t d=r.reg(); ctx->regs[d]=(uint64_t)(int64_t)(int8_t)r.u8(); break; }
        case VMOP_MOV_RI32: { uint8_t d=r.reg(); ctx->regs[d]=(uint64_t)(int64_t)r.i32(); break; }
        case VMOP_MOV_RI64: { uint8_t d=r.reg(); ctx->regs[d]=r.u64(); break; }

        // MOV reg<-mem
        case VMOP_MOV_RM8:    { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=*(uint8_t*)a; break; }
        case VMOP_MOV_RM16:   { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=*(uint16_t*)a; break; }
        case VMOP_MOV_RM32:   { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=*(uint32_t*)a; break; }
        case VMOP_MOV_RM64:   { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=*(uint64_t*)a; break; }
        case VMOP_MOVZX_RM8:  { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=(uint8_t)*(uint8_t*)a; break; }
        case VMOP_MOVZX_RM16: { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=(uint16_t)*(uint16_t*)a; break; }
        case VMOP_MOVSX_RM8:  { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=(uint64_t)(int64_t)*(int8_t*)a; break; }
        case VMOP_MOVSX_RM16: { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=(uint64_t)(int64_t)*(int16_t*)a; break; }
        case VMOP_MOVSX_RM32: { uint8_t d=r.reg(); uint64_t a=MA(r,ctx); ctx->regs[d]=(uint64_t)(int64_t)*(int32_t*)a; break; }

        // MOV mem<-reg
        case VMOP_MOV_MR8:  { uint64_t a=MA(r,ctx); uint8_t s=r.reg(); *(uint8_t*) a=(uint8_t) ctx->regs[s]; break; }
        case VMOP_MOV_MR16: { uint64_t a=MA(r,ctx); uint8_t s=r.reg(); *(uint16_t*)a=(uint16_t)ctx->regs[s]; break; }
        case VMOP_MOV_MR32: { uint64_t a=MA(r,ctx); uint8_t s=r.reg(); *(uint32_t*)a=(uint32_t)ctx->regs[s]; break; }
        case VMOP_MOV_MR64: { uint64_t a=MA(r,ctx); uint8_t s=r.reg(); *(uint64_t*)a=ctx->regs[s]; break; }
        case VMOP_MOV_MI8:  { uint64_t a=MA(r,ctx); *(uint8_t*)a =r.u8();  break; }
        case VMOP_MOV_MI32: { uint64_t a=MA(r,ctx); *(int32_t*)a=r.i32(); break; }

        // LEA
        case VMOP_LEA: {
            uint8_t d=r.reg(),b=r.reg(),idx=r.reg(),sc=r.u8(); int32_t dp=r.i32();
            uint64_t ea=ctx->regs[b]+dp;
            if(idx!=0xFF) ea+=ctx->regs[idx]*(1ULL<<sc);
            ctx->regs[d]=ea; break;
        }
        // VMOP_LEA_ABS: bytecode stores u32 RVA; add image_base for ASLR safety.
        case VMOP_LEA_ABS: { uint8_t d=r.reg(); ctx->regs[d]=image_base+r.u32(); break; }

        // PUSH/POP
        case VMOP_PUSH_R:  { uint8_t s=r.reg(); ctx->regs[VR_RSP]-=8; *(uint64_t*)ctx->regs[VR_RSP]=ctx->regs[s]; break; }
        case VMOP_POP_R:   { uint8_t d=r.reg(); ctx->regs[d]=*(uint64_t*)ctx->regs[VR_RSP]; ctx->regs[VR_RSP]+=8; break; }
        case VMOP_PUSH_I8: { int8_t  v=(int8_t)r.u8();  ctx->regs[VR_RSP]-=8; *(int64_t*)ctx->regs[VR_RSP]=v; break; }
        case VMOP_PUSH_I32:{ int32_t v=r.i32(); ctx->regs[VR_RSP]-=8; *(int64_t*)ctx->regs[VR_RSP]=v; break; }
        case VMOP_XCHG_RR: { uint8_t a=r.reg(),b=r.reg(); uint64_t t=ctx->regs[a]; ctx->regs[a]=ctx->regs[b]; ctx->regs[b]=t; break; }

        // ALU reg,reg
        case VMOP_ADD_RR: { uint8_t d=r.reg(),s=r.reg(); uint64_t a=ctx->regs[d],b=ctx->regs[s]; ctx->regs[d]=a+b; flags_add(ctx,a,b,a+b); break; }
        case VMOP_SUB_RR: { uint8_t d=r.reg(),s=r.reg(); uint64_t a=ctx->regs[d],b=ctx->regs[s]; ctx->regs[d]=a-b; flags_sub(ctx,a,b,a-b); break; }
        case VMOP_ADC_RR: { uint8_t d=r.reg(),s=r.reg(); uint64_t cf=(ctx->regs[VR_RFLAGS]>>0)&1,a=ctx->regs[d],b=ctx->regs[s],res=a+b+cf; ctx->regs[d]=res; flags_adc(ctx,a,b,cf,res); break; }
        case VMOP_SBB_RR: { uint8_t d=r.reg(),s=r.reg(); uint64_t cf=(ctx->regs[VR_RFLAGS]>>0)&1,a=ctx->regs[d],b=ctx->regs[s],res=a-b-cf; ctx->regs[d]=res; flags_sbb(ctx,a,b,cf,res); break; }
        case VMOP_AND_RR: { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]&=ctx->regs[s]; flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_OR_RR:  { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]|=ctx->regs[s]; flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_XOR_RR: { uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]^=ctx->regs[s]; flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_CMP_RR: { uint8_t d=r.reg(),s=r.reg(); uint64_t a=ctx->regs[d],b=ctx->regs[s]; flags_sub(ctx,a,b,a-b); break; }
        case VMOP_TEST_RR:{ uint8_t d=r.reg(),s=r.reg(); flags_logic(ctx,ctx->regs[d]&ctx->regs[s]); break; }
        case VMOP_IMUL_RR:{ uint8_t d=r.reg(),s=r.reg(); ctx->regs[d]=(uint64_t)((int64_t)ctx->regs[d]*(int64_t)ctx->regs[s]); break; }

        // ALU reg,imm8
        case VMOP_ADD_RI8: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d],b=(uint64_t)(int64_t)(int8_t)r.u8(); ctx->regs[d]=a+b; flags_add(ctx,a,b,a+b); break; }
        case VMOP_SUB_RI8: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d],b=(uint64_t)(int64_t)(int8_t)r.u8(); ctx->regs[d]=a-b; flags_sub(ctx,a,b,a-b); break; }
        case VMOP_ADC_RI8: { uint8_t d=r.reg(); uint64_t cf=(ctx->regs[VR_RFLAGS]>>0)&1,a=ctx->regs[d],b=(uint64_t)(int64_t)(int8_t)r.u8(),res=a+b+cf; ctx->regs[d]=res; flags_adc(ctx,a,b,cf,res); break; }
        case VMOP_SBB_RI8: { uint8_t d=r.reg(); uint64_t cf=(ctx->regs[VR_RFLAGS]>>0)&1,a=ctx->regs[d],b=(uint64_t)(int64_t)(int8_t)r.u8(),res=a-b-cf; ctx->regs[d]=res; flags_sbb(ctx,a,b,cf,res); break; }
        case VMOP_AND_RI8: { uint8_t d=r.reg(); ctx->regs[d]&=(uint64_t)(int64_t)(int8_t)r.u8(); flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_OR_RI8:  { uint8_t d=r.reg(); ctx->regs[d]|=(uint64_t)(int64_t)(int8_t)r.u8(); flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_XOR_RI8: { uint8_t d=r.reg(); ctx->regs[d]^=(uint64_t)(int64_t)(int8_t)r.u8(); flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_CMP_RI8: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d],b=(uint64_t)(int64_t)(int8_t)r.u8(); flags_sub(ctx,a,b,a-b); break; }

        // ALU reg,imm32
        case VMOP_ADD_RI32: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d],b=(uint64_t)(int64_t)r.i32(); ctx->regs[d]=a+b; flags_add(ctx,a,b,a+b); break; }
        case VMOP_SUB_RI32: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d],b=(uint64_t)(int64_t)r.i32(); ctx->regs[d]=a-b; flags_sub(ctx,a,b,a-b); break; }
        case VMOP_ADC_RI32: { uint8_t d=r.reg(); uint64_t cf=(ctx->regs[VR_RFLAGS]>>0)&1,a=ctx->regs[d],b=(uint64_t)(int64_t)r.i32(),res=a+b+cf; ctx->regs[d]=res; flags_adc(ctx,a,b,cf,res); break; }
        case VMOP_SBB_RI32: { uint8_t d=r.reg(); uint64_t cf=(ctx->regs[VR_RFLAGS]>>0)&1,a=ctx->regs[d],b=(uint64_t)(int64_t)r.i32(),res=a-b-cf; ctx->regs[d]=res; flags_sbb(ctx,a,b,cf,res); break; }
        case VMOP_AND_RI32: { uint8_t d=r.reg(); ctx->regs[d]&=(uint64_t)(int64_t)r.i32(); flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_OR_RI32:  { uint8_t d=r.reg(); ctx->regs[d]|=(uint64_t)(int64_t)r.i32(); flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_XOR_RI32: { uint8_t d=r.reg(); ctx->regs[d]^=(uint64_t)(int64_t)r.i32(); flags_logic(ctx,ctx->regs[d]); break; }
        case VMOP_CMP_RI32: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d],b=(uint64_t)(int64_t)r.i32(); flags_sub(ctx,a,b,a-b); break; }
        case VMOP_TEST_RI32:{ uint8_t d=r.reg(); flags_logic(ctx,ctx->regs[d]&(uint64_t)(int64_t)r.i32()); break; }
        case VMOP_IMUL_RRI32:{ uint8_t d=r.reg(),s=r.reg(); int32_t imm=r.i32(); ctx->regs[d]=(uint64_t)((int64_t)ctx->regs[s]*(int64_t)imm); break; }

        // Unary
        case VMOP_NOT_R: { uint8_t d=r.reg(); ctx->regs[d]=~ctx->regs[d]; break; }
        case VMOP_NEG_R: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d]; ctx->regs[d]=~a+1; flags_sub(ctx,0,a,~a+1); break; }
        case VMOP_INC_R: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d]; ctx->regs[d]=a+1; flags_add(ctx,a,1,a+1); break; }
        case VMOP_DEC_R: { uint8_t d=r.reg(); uint64_t a=ctx->regs[d]; ctx->regs[d]=a-1; flags_sub(ctx,a,1,a-1); break; }
        case VMOP_MUL_R: { uint8_t s=r.reg(); unsigned __int64 hi; ctx->regs[VR_RAX]=_umul128(ctx->regs[VR_RAX],ctx->regs[s],&hi); ctx->regs[VR_RDX]=hi; break; }
        case VMOP_IMUL_R:{ uint8_t s=r.reg(); __int64 hi; ctx->regs[VR_RAX]=(uint64_t)_mul128((int64_t)ctx->regs[VR_RAX],(int64_t)ctx->regs[s],&hi); ctx->regs[VR_RDX]=(uint64_t)hi; break; }
        case VMOP_DIV_R: { uint8_t s=r.reg(); uint64_t lo=ctx->regs[VR_RAX],d=ctx->regs[s]; if(d){ctx->regs[VR_RAX]=lo/d;ctx->regs[VR_RDX]=lo%d;} break; }
        case VMOP_IDIV_R:{ uint8_t s=r.reg(); int64_t lo=(int64_t)ctx->regs[VR_RAX],d=(int64_t)ctx->regs[s]; if(d){ctx->regs[VR_RAX]=(uint64_t)(lo/d);ctx->regs[VR_RDX]=(uint64_t)(lo%d);} break; }

        // Shifts
        case VMOP_SHL_RI: { uint8_t d=r.reg(),c=r.u8(); ctx->regs[d]<<=c; break; }
        case VMOP_SHR_RI: { uint8_t d=r.reg(),c=r.u8(); ctx->regs[d]>>=c; break; }
        case VMOP_SAR_RI: { uint8_t d=r.reg(),c=r.u8(); ctx->regs[d]=(uint64_t)((int64_t)ctx->regs[d]>>c); break; }
        case VMOP_ROL_RI: { uint8_t d=r.reg(),c=r.u8(); uint64_t v=ctx->regs[d]; ctx->regs[d]=(v<<c)|(v>>(64-c)); break; }
        case VMOP_ROR_RI: { uint8_t d=r.reg(),c=r.u8(); uint64_t v=ctx->regs[d]; ctx->regs[d]=(v>>c)|(v<<(64-c)); break; }
        case VMOP_SHL_RC: { uint8_t d=r.reg(),c=(uint8_t)(ctx->regs[VR_RCX]&63); ctx->regs[d]<<=c; break; }
        case VMOP_SHR_RC: { uint8_t d=r.reg(),c=(uint8_t)(ctx->regs[VR_RCX]&63); ctx->regs[d]>>=c; break; }
        case VMOP_SAR_RC: { uint8_t d=r.reg(),c=(uint8_t)(ctx->regs[VR_RCX]&63); ctx->regs[d]=(uint64_t)((int64_t)ctx->regs[d]>>c); break; }

        // Branches (offset = absolute position in bytecode)
        case VMOP_JMP:  { int32_t o=r.i32(); r.pos=(uint32_t)o; break; }
        case VMOP_JE:   { int32_t o=r.i32(); if(eval_cond(4,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JNE:  { int32_t o=r.i32(); if(eval_cond(5,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JL:   { int32_t o=r.i32(); if(eval_cond(12,ctx)) r.pos=(uint32_t)o; break; }
        case VMOP_JGE:  { int32_t o=r.i32(); if(eval_cond(13,ctx)) r.pos=(uint32_t)o; break; }
        case VMOP_JLE:  { int32_t o=r.i32(); if(eval_cond(14,ctx)) r.pos=(uint32_t)o; break; }
        case VMOP_JG:   { int32_t o=r.i32(); if(eval_cond(15,ctx)) r.pos=(uint32_t)o; break; }
        case VMOP_JB:   { int32_t o=r.i32(); if(eval_cond(2,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JAE:  { int32_t o=r.i32(); if(eval_cond(3,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JBE:  { int32_t o=r.i32(); if(eval_cond(6,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JA:   { int32_t o=r.i32(); if(eval_cond(7,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JS:   { int32_t o=r.i32(); if(eval_cond(8,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JNS:  { int32_t o=r.i32(); if(eval_cond(9,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JO:   { int32_t o=r.i32(); if(eval_cond(0,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JNO:  { int32_t o=r.i32(); if(eval_cond(1,ctx))  r.pos=(uint32_t)o; break; }
        case VMOP_JP:   { int32_t o=r.i32(); if(eval_cond(10,ctx)) r.pos=(uint32_t)o; break; }
        case VMOP_JNP:  { int32_t o=r.i32(); if(eval_cond(11,ctx)) r.pos=(uint32_t)o; break; }
        case VMOP_JRCXZ:{ int32_t o=r.i32(); if(!ctx->regs[VR_RCX]) r.pos=(uint32_t)o; break; }

        // CALL (native dispatch)
        // Bytecode stores u32 RVA; add image_base for ASLR-safe absolute address.
        case VMOP_CALL_ABS: {
            uint64_t target = image_base + r.u32();
            typedef uint64_t(*fn4)(uint64_t,uint64_t,uint64_t,uint64_t);
            ctx->regs[VR_RAX]=((fn4)target)(ctx->regs[VR_RCX],ctx->regs[VR_RDX],
                                              ctx->regs[VR_R8], ctx->regs[VR_R9]);
            break;
        }
        case VMOP_CALL_R: {
            uint8_t s=r.reg();
            typedef uint64_t(*fn4)(uint64_t,uint64_t,uint64_t,uint64_t);
            ctx->regs[VR_RAX]=((fn4)ctx->regs[s])(ctx->regs[VR_RCX],ctx->regs[VR_RDX],
                                                    ctx->regs[VR_R8], ctx->regs[VR_R9]);
            break;
        }
        // Indirect call through memory (IAT slot): target = *(image_base + rva32)
        // Handles FF/2 mod=0 rm=5 (call [rip+disp]) lifted by the obfuscator.
        case VMOP_CALL_MEM_ABS: {
            uint64_t target = *(uint64_t*)(image_base + r.u32());
            typedef uint64_t(*fn4)(uint64_t,uint64_t,uint64_t,uint64_t);
            ctx->regs[VR_RAX]=((fn4)target)(ctx->regs[VR_RCX],ctx->regs[VR_RDX],
                                             ctx->regs[VR_R8], ctx->regs[VR_R9]);
            break;
        }

        case VMOP_SETCC:  { uint8_t c=r.u8(),d=r.reg(); ctx->regs[d]=eval_cond(c,ctx)?1:0; break; }
        case VMOP_CMOVCC: { uint8_t c=r.u8(),d=r.reg(),s=r.reg(); if(eval_cond(c,ctx)) ctx->regs[d]=ctx->regs[s]; break; }

        case VMOP_NATIVE: { uint8_t len=r.u8(); exec_native(bytecode+r.pos,len,ctx); r.pos+=len; break; }

        default: return; // unknown — halt
        }
    }
#undef MA
}

} // namespace vm
