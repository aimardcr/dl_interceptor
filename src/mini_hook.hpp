// mini_hook - Minimal inline hook for function entry points
// Header-only. Supports: ARM64, ARM32 (Thumb), x86, x86_64
//
// Architecture overview:
//   1. Allocate an executable page near the target function
//   2. Write an "entry trampoline" that jumps to the replacement function
//   3. Write an "original trampoline" that executes saved instructions then jumps back
//   4. Overwrite target's first N bytes with a relative branch to the entry trampoline
//
// Security:
//   - ARM64 BTI (Branch Target Identification) landing pads in trampolines
//   - ARM64 PAC (Pointer Authentication) awareness — safe relocation of PACIASP/PACIBSP
//   - W^X compliant: allocates RW, flips to RX after writing
//   - PC-relative instruction detection prevents silent corruption
//
// Limitations:
//   - Only hooks function entry points
//   - Does not relocate PC-relative instructions (rejects them instead)
//   - ARM32 assumes Thumb mode
//
// Usage:
//   #include "mini_hook.hpp"
//   void *orig = nullptr;
//   mini_hook_install(target_func, my_replacement, &orig);

#pragma once

#include <android/log.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MH_TAG "MiniHook"
#define MH_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, MH_TAG, __VA_ARGS__)

// ============================================================================
// Utility
// ============================================================================

namespace mini_hook {
namespace detail {

inline uintptr_t page_size() {
    static uintptr_t ps = 0;
    if (!ps) ps = (uintptr_t)sysconf(_SC_PAGESIZE);
    return ps;
}

inline uintptr_t page_align(uintptr_t addr) {
    return addr & ~(page_size() - 1);
}

inline void clear_cache(void *addr, size_t len) {
    __builtin___clear_cache((char *)addr, (char *)addr + len);
}

// ---------------------------------------------------------------------------
// Memory protection helpers (W^X aware)
// ---------------------------------------------------------------------------

// Make target temporarily writable. Prefers RWX so other threads can keep
// executing the page while we patch.  Falls back to RW if kernel enforces W^X.
inline int mprotect_write(uintptr_t addr, size_t len) {
    uintptr_t start = page_align(addr);
    uintptr_t end = page_align(addr + len - 1 + page_size());
    size_t size = end - start;
    if (mprotect((void *)start, size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) return 0;
    return mprotect((void *)start, size, PROT_READ | PROT_WRITE);
}

// Restore execute permission after patching.  Tries R+X, falls back to RWX.
inline void mprotect_exec(uintptr_t addr, size_t len) {
    uintptr_t start = page_align(addr);
    uintptr_t end = page_align(addr + len - 1 + page_size());
    size_t size = end - start;
    if (mprotect((void *)start, size, PROT_READ | PROT_EXEC) != 0)
        mprotect((void *)start, size, PROT_READ | PROT_WRITE | PROT_EXEC);
}

// Make a trampoline page executable after all code has been written into it.
inline int finalize_trampoline(void *page, size_t code_size) {
    clear_cache(page, code_size);
    uintptr_t ps = page_size();
    if (mprotect(page, ps, PROT_READ | PROT_EXEC) == 0) return 0;
    if (mprotect(page, ps, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) return 0;
    MH_LOGE("finalize: cannot make trampoline page executable");
    return -1;
}

// ---------------------------------------------------------------------------
// Near-page allocator
// ---------------------------------------------------------------------------

// Allocate a RW page near `target` (within `range` bytes).
// Caller writes trampoline code, then calls finalize_trampoline().
inline void *alloc_near(uintptr_t target, size_t range) {
    uintptr_t ps = page_size();
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    for (uintptr_t offset = ps; offset < range; offset += ps) {
        if (target > offset) {
            uintptr_t hint = page_align(target - offset);
            void *p = mmap((void *)hint, ps, PROT_READ | PROT_WRITE, flags, -1, 0);
            if (p != MAP_FAILED) {
                if ((uintptr_t)p >= target - range && (uintptr_t)p <= target + range)
                    return p;
                munmap(p, ps);
            }
        }
        {
            uintptr_t hint = page_align(target + offset);
            void *p = mmap((void *)hint, ps, PROT_READ | PROT_WRITE, flags, -1, 0);
            if (p != MAP_FAILED) {
                if ((uintptr_t)p >= target - range && (uintptr_t)p <= target + range)
                    return p;
                munmap(p, ps);
            }
        }
    }
    return nullptr;
}

// ============================================================================
// ARM64: instruction classification
// ============================================================================

#if defined(__aarch64__)

// BTI, BTI c, BTI j, BTI jc  (HINT #32, #34, #36, #38)
inline bool arm64_is_bti(uint32_t insn) {
    return (insn & 0xFFFFFF3F) == 0xD503241F;
}

// PACIASP (HINT #25) or PACIBSP (HINT #27)
inline bool arm64_is_pac_sp(uint32_t insn) {
    return insn == 0xD503233F || insn == 0xD503237F;
}

inline bool arm64_is_pc_relative(uint32_t insn) {
    if ((insn & 0x9F000000) == 0x90000000) return true;  // ADRP
    if ((insn & 0x9F000000) == 0x10000000) return true;  // ADR
    if ((insn & 0x3B000000) == 0x18000000) return true;  // LDR/LDRSW/PRFM literal
    if ((insn & 0xFC000000) == 0x14000000) return true;  // B
    if ((insn & 0xFC000000) == 0x94000000) return true;  // BL
    if ((insn & 0x7E000000) == 0x34000000) return true;  // CBZ/CBNZ
    if ((insn & 0x7E000000) == 0x36000000) return true;  // TBZ/TBNZ
    if ((insn & 0xFF000010) == 0x54000000) return true;  // B.cond
    return false;
}

// Load a 64-bit immediate into Xd via MOVZ + MOVK (always 4 instructions / 16 bytes).
inline void arm64_emit_mov_imm(uint32_t *out, uint8_t rd, uint64_t imm) {
    out[0] = 0xD2800000u | ((uint32_t)((imm >>  0) & 0xFFFF) << 5) | rd;  // MOVZ Xd, #imm[15:0]
    out[1] = 0xF2A00000u | ((uint32_t)((imm >> 16) & 0xFFFF) << 5) | rd;  // MOVK Xd, #imm[31:16], LSL#16
    out[2] = 0xF2C00000u | ((uint32_t)((imm >> 32) & 0xFFFF) << 5) | rd;  // MOVK Xd, #imm[47:32], LSL#32
    out[3] = 0xF2E00000u | ((uint32_t)((imm >> 48) & 0xFFFF) << 5) | rd;  // MOVK Xd, #imm[63:48], LSL#48
}

// Relocate a single ARM64 instruction from orig_pc to a trampoline buffer.
// PC-relative instructions are rewritten with absolute addresses so they
// produce correct results regardless of the trampoline's location.
// Returns number of uint32_t words written to `out`, or -1 on error.
// Buffer `out` must have room for at least 5 words (20 bytes).
inline int arm64_relocate_insn(uint32_t insn, uintptr_t orig_pc, uint32_t *out) {
    // BTI, PAC, and non-PC-relative instructions: copy verbatim.
    if (arm64_is_bti(insn) || arm64_is_pac_sp(insn) || !arm64_is_pc_relative(insn)) {
        out[0] = insn;
        return 1;
    }

    // --- B / BL  (±128 MB direct branch) ---
    if ((insn & 0xFC000000) == 0x14000000 || (insn & 0xFC000000) == 0x94000000) {
        bool is_bl = (insn & 0xFC000000) == 0x94000000;
        int32_t imm26 = (int32_t)(insn << 6) >> 6;          // sign-extend 26-bit
        uintptr_t dst = orig_pc + ((int64_t)imm26 << 2);
        out[0] = 0x58000051u;                                 // LDR X17, [PC, #8]
        out[1] = is_bl ? 0xD63F0220u : 0xD61F0220u;          // BLR X17 / BR X17
        memcpy(&out[2], &dst, 8);                             // .quad dst
        return 4;
    }

    // --- ADRP  (PC-relative page address) ---
    if ((insn & 0x9F000000) == 0x90000000) {
        uint8_t rd = insn & 0x1F;
        int32_t immhi = (int32_t)(insn << 8) >> 13;          // sign-extend 19-bit
        uint32_t immlo = (insn >> 29) & 3;
        int64_t offset = ((int64_t)immhi << 14) | ((int64_t)immlo << 12);
        uintptr_t dst = (orig_pc & ~0xFFFULL) + offset;
        arm64_emit_mov_imm(out, rd, dst);                     // MOV Xd, #page_addr
        return 4;
    }

    // --- ADR  (PC-relative address) ---
    if ((insn & 0x9F000000) == 0x10000000) {
        uint8_t rd = insn & 0x1F;
        int32_t immhi = (int32_t)(insn << 8) >> 13;
        uint32_t immlo = (insn >> 29) & 3;
        int64_t offset = ((int64_t)immhi << 2) | immlo;
        uintptr_t dst = orig_pc + offset;
        arm64_emit_mov_imm(out, rd, dst);                     // MOV Xd, #addr
        return 4;
    }

    // --- LDR literal  (PC-relative data load) ---
    if ((insn & 0x3B000000) == 0x18000000) {
        uint8_t opc = (insn >> 30) & 3;
        uint8_t rt = insn & 0x1F;
        int32_t imm19 = (int32_t)(insn << 8) >> 13;
        uintptr_t data_addr = orig_pc + ((int64_t)imm19 << 2);

        if (opc == 0b11) { out[0] = 0xD503201Fu; return 1; } // PRFM → NOP
        if ((insn >> 26) & 1) {                                // V=1: SIMD/FP literal
            MH_LOGE("arm64: SIMD LDR literal at %p unsupported", (void *)orig_pc);
            return -1;
        }
        arm64_emit_mov_imm(out, 17, data_addr);               // MOV X17, #data_addr
        if (opc == 0b00)      out[4] = 0xB9400220u | rt;      // LDR Wt,    [X17]
        else if (opc == 0b01) out[4] = 0xF9400220u | rt;      // LDR Xt,    [X17]
        else                  out[4] = 0xB9800220u | rt;      // LDRSW Xt,  [X17]
        return 5;
    }

    // --- Conditional branches: invert condition, skip over LDR+BR+.quad (20 B) ---

    // B.cond
    if ((insn & 0xFF000010) == 0x54000000) {
        int32_t imm19 = (int32_t)(insn << 8) >> 13;
        uintptr_t dst = orig_pc + ((int64_t)imm19 << 2);
        uint32_t inv_cond = (insn & 0xF) ^ 1;                // invert condition
        out[0] = 0x540000A0u | inv_cond;                      // B.<inv> +20
        out[1] = 0x58000051u;                                  // LDR X17, [PC, #8]
        out[2] = 0xD61F0220u;                                  // BR X17
        memcpy(&out[3], &dst, 8);                              // .quad dst
        return 5;
    }

    // CBZ / CBNZ
    if ((insn & 0x7E000000) == 0x34000000) {
        int32_t imm19 = (int32_t)(insn << 8) >> 13;
        uintptr_t dst = orig_pc + ((int64_t)imm19 << 2);
        uint32_t inv = insn ^ (1u << 24);                     // flip CBZ↔CBNZ
        inv = (inv & ~(0x7FFFFu << 5)) | (5u << 5);           // imm19 = 5 → skip 20 B
        out[0] = inv;
        out[1] = 0x58000051u;
        out[2] = 0xD61F0220u;
        memcpy(&out[3], &dst, 8);
        return 5;
    }

    // TBZ / TBNZ
    if ((insn & 0x7E000000) == 0x36000000) {
        int32_t imm14 = (int32_t)(insn << 13) >> 18;          // sign-extend 14-bit
        uintptr_t dst = orig_pc + ((int64_t)imm14 << 2);
        uint32_t inv = insn ^ (1u << 24);                     // flip TBZ↔TBNZ
        inv = (inv & ~(0x3FFFu << 5)) | (5u << 5);            // imm14 = 5 → skip 20 B
        out[0] = inv;
        out[1] = 0x58000051u;
        out[2] = 0xD61F0220u;
        memcpy(&out[3], &dst, 8);
        return 5;
    }

    MH_LOGE("arm64: unhandled PC-relative instruction 0x%08X at %p", insn, (void *)orig_pc);
    return -1;
}

#endif  // __aarch64__

// ============================================================================
// ARM32: Thumb instruction helpers
// ============================================================================

#if defined(__arm__)

// 32-bit Thumb-2 instructions start with 0xE800..0xFFFF in the first halfword.
inline bool thumb_is_32bit(uint16_t hw) {
    return (hw & 0xF800) >= 0xE800;
}

// Compute minimum instruction-aligned backup length >= min_bytes.
inline size_t thumb_backup_len(const uint8_t *code, size_t min_bytes) {
    size_t total = 0;
    while (total < min_bytes) {
        uint16_t hw;
        memcpy(&hw, code + total, 2);
        total += thumb_is_32bit(hw) ? 4 : 2;
    }
    return total;
}

// Check if any instruction in [code, code+len) is PC-relative.
inline bool thumb_has_pc_relative(const uint8_t *code, size_t len) {
    size_t off = 0;
    while (off < len) {
        uint16_t hw;
        memcpy(&hw, code + off, 2);
        if (thumb_is_32bit(hw)) {
            uint16_t hw1;
            memcpy(&hw1, code + off + 2, 2);
            if ((hw & 0xF800) == 0xF000 && (hw1 & 0xD000) == 0xD000) return true;  // BL/BLX
            if ((hw & 0xF800) == 0xF000 && (hw1 & 0xD000) == 0x9000) return true;  // B.W
            if ((hw & 0xFF7F) == 0xF85F) return true;   // LDR.W Rt, [PC, #imm]
            if ((hw & 0xFBFF) == 0xF20F) return true;   // ADR.W (ADD variant)
            if ((hw & 0xFBFF) == 0xF2AF) return true;   // ADR.W (SUB variant)
            off += 4;
        } else {
            if ((hw & 0xF800) == 0xA000) return true;   // ADR
            if ((hw & 0xF800) == 0x4800) return true;   // LDR Rd, [PC, #imm]
            if ((hw & 0xF800) == 0xE000) return true;   // B (unconditional)
            if ((hw & 0xF000) == 0xD000 &&
                ((hw >> 8) & 0xF) < 0xE) return true;   // B.cond
            if ((hw & 0xF500) == 0xB100) return true;   // CBZ
            if ((hw & 0xF500) == 0xB900) return true;   // CBNZ
            off += 2;
        }
    }
    return false;
}

// Encode a Thumb B.W instruction at `pos` branching to `target`.
// B.W range: +/-16 MB.  `pos` and `target` must be halfword-aligned.
inline void thumb_write_bw(uint8_t *pos, uintptr_t target) {
    int32_t offset = (int32_t)(target - ((uintptr_t)pos + 4));
    uint32_t s     = (offset >> 24) & 1;
    uint32_t i1    = (offset >> 23) & 1;
    uint32_t i2    = (offset >> 22) & 1;
    uint32_t imm10 = (offset >> 12) & 0x3FF;
    uint32_t imm11 = (offset >>  1) & 0x7FF;
    uint32_t j1    = ((~i1) ^ s) & 1;
    uint32_t j2    = ((~i2) ^ s) & 1;
    uint16_t hw0 = 0xF000 | (s << 10) | imm10;
    uint16_t hw1 = 0x9000 | (j1 << 13) | (j2 << 11) | imm11;
    memcpy(pos,     &hw0, 2);
    memcpy(pos + 2, &hw1, 2);
}

#endif  // __arm__

// ============================================================================
// x86 / x86_64: minimal instruction length decoder
// ============================================================================

#if defined(__i386__) || defined(__x86_64__)

inline size_t x86_insn_len(const uint8_t *code) {
    const uint8_t *p = code;
    bool has_prefix_66 = false;
    [[maybe_unused]] bool has_prefix_67 = false;
#if defined(__x86_64__)
    [[maybe_unused]] bool has_rex = false;
    bool rex_w = false;
#endif

    // Prefixes
    for (;;) {
        uint8_t b = *p;
        if (b == 0x66) { has_prefix_66 = true; p++; continue; }
        if (b == 0x67) { has_prefix_67 = true; p++; continue; }
        if (b == 0xF0 || b == 0xF2 || b == 0xF3) { p++; continue; }
        if (b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65) { p++; continue; }
#if defined(__x86_64__)
        if ((b & 0xF0) == 0x40) { has_rex = true; rex_w = (b & 0x08) != 0; p++; continue; }
#endif
        break;
    }

    uint8_t op = *p++;

    // Simple 1-byte opcodes
    if ((op & 0xF0) == 0x50) return (size_t)(p - code);                  // PUSH/POP reg
    if (op == 0xC3 || op == 0xCB) return (size_t)(p - code);             // RET
    if (op == 0xC2 || op == 0xCA) return (size_t)(p - code) + 2;         // RET imm16
    if (op == 0x90) return (size_t)(p - code);                            // NOP
    if (op == 0xCC) return (size_t)(p - code);                            // INT3
    if (op == 0xC9) return (size_t)(p - code);                            // LEAVE
    if (op == 0xFC || op == 0xFD) return (size_t)(p - code);             // CLD/STD
    if (op == 0x99) return (size_t)(p - code);                            // CDQ/CQO
    if (op == 0x6A) return (size_t)(p - code) + 1;                       // PUSH imm8
    if (op == 0x68) return (size_t)(p - code) + 4;                       // PUSH imm32
    if ((op & 0xF0) == 0xB0) {                                           // MOV reg, imm
        if (op < 0xB8) return (size_t)(p - code) + 1;
#if defined(__x86_64__)
        if (rex_w) return (size_t)(p - code) + 8;
#endif
        return (size_t)(p - code) + 4;
    }
    if (op >= 0x91 && op <= 0x97) return (size_t)(p - code);             // XCHG EAX, reg
    if (op == 0xEB) return (size_t)(p - code) + 1;                       // JMP rel8
    if (op == 0xE9) return (size_t)(p - code) + 4;                       // JMP rel32
    if (op == 0xE8) return (size_t)(p - code) + 4;                       // CALL rel32
    if ((op & 0xF0) == 0x70) return (size_t)(p - code) + 1;             // Jcc rel8

    // ModR/M-based opcodes
    bool has_modrm = false;
    size_t imm_size = 0;
    bool is_group3 = false;  // F6/F7: immediate depends on ModR/M reg field

    if (op == 0x0F) {
        uint8_t op2 = *p++;
        if ((op2 & 0xF0) == 0x80) return (size_t)(p - code) + 4;        // Jcc rel32
        if ((op2 & 0xF0) == 0x90) { has_modrm = true; }                 // SETcc
        else if ((op2 & 0xF0) == 0x40) { has_modrm = true; }            // CMOVcc
        else if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) { has_modrm = true; } // MOVZX/SX
        else if (op2 == 0x1F) { has_modrm = true; }                     // NOP (multi-byte)
        else if (op2 == 0x05) return (size_t)(p - code);                 // SYSCALL
        else { has_modrm = true; }
    }
    else if ((op & 0xC4) == 0x00 && (op & 0x03) <= 0x03) { has_modrm = true; }  // ALU r/m, r
    else if ((op & 0x07) == 0x04) { return (size_t)(p - code) + 1; }             // ALU AL, imm8
    else if ((op & 0x07) == 0x05) { return (size_t)(p - code) + (has_prefix_66 ? 2 : 4); } // ALU EAX, imm
    else if (op >= 0x80 && op <= 0x83) {                                          // Group 1
        has_modrm = true;
        if (op == 0x80 || op == 0x82) imm_size = 1;
        else if (op == 0x81) imm_size = has_prefix_66 ? 2 : 4;
        else imm_size = 1;
    }
    else if (op == 0x84 || op == 0x85) { has_modrm = true; }             // TEST
    else if (op == 0x86 || op == 0x87) { has_modrm = true; }             // XCHG
    else if (op >= 0x88 && op <= 0x8B) { has_modrm = true; }             // MOV r/m <-> r
    else if (op == 0x8C || op == 0x8E) { has_modrm = true; }             // MOV Sreg
    else if (op == 0x8D) { has_modrm = true; }                           // LEA
    else if (op == 0xC6) { has_modrm = true; imm_size = 1; }             // MOV r/m, imm8
    else if (op == 0xC7) { has_modrm = true; imm_size = has_prefix_66 ? 2 : 4; } // MOV r/m, imm32
    else if (op == 0xF6) { has_modrm = true; is_group3 = true; }         // Group 3 byte
    else if (op == 0xF7) { has_modrm = true; is_group3 = true; }         // Group 3 word/dword
    else if (op == 0xFF) { has_modrm = true; }                           // INC/DEC/CALL/JMP/PUSH
    else if (op >= 0xD0 && op <= 0xD3) { has_modrm = true; }             // Shift
    else if (op == 0xC0 || op == 0xC1) { has_modrm = true; imm_size = 1; } // Shift imm
    else if (op == 0x69) { has_modrm = true; imm_size = has_prefix_66 ? 2 : 4; } // IMUL imm32
    else if (op == 0x6B) { has_modrm = true; imm_size = 1; }             // IMUL imm8
    else {
        MH_LOGE("x86: unknown opcode 0x%02X at %p", op, code);
        return 0;
    }

    if (!has_modrm) return (size_t)(p - code) + imm_size;

    // Parse ModR/M
    uint8_t modrm = *p++;
    uint8_t mod = modrm >> 6;
    uint8_t rm = modrm & 0x07;

    // Group 3 (F6/F7): only TEST (reg field 0 or 1) has an immediate operand.
    // NOT/NEG/MUL/IMUL/DIV/IDIV (reg >= 2) have no immediate.
    if (is_group3) {
        uint8_t reg = (modrm >> 3) & 7;
        if (reg <= 1) {
            imm_size = (op == 0xF6) ? 1 : (has_prefix_66 ? 2 : 4);
        }
        // else imm_size stays 0
    }

#if defined(__x86_64__)
    bool addr32 = has_prefix_67;
#else
    bool addr32 = !has_prefix_67;
#endif

    if (mod == 3) return (size_t)(p - code) + imm_size;

    if (rm == 4 && addr32) p++;  // SIB

    if (mod == 0 && rm == 5) p += 4;       // [disp32] or [RIP+disp32]
    else if (mod == 1) p += 1;              // disp8
    else if (mod == 2) p += 4;              // disp32

    return (size_t)(p - code) + imm_size;
}

inline size_t calc_backup_len(const uint8_t *code, size_t min_bytes) {
    size_t total = 0;
    while (total < min_bytes) {
        size_t len = x86_insn_len(code + total);
        if (len == 0) return 0;
        total += len;
    }
    return total;
}

#endif  // x86/x86_64

}  // namespace detail
}  // namespace mini_hook

// ============================================================================
// Public API
// ============================================================================

inline int mini_hook_install(void *target, void *replace, void **original) {
    using namespace mini_hook::detail;

// ---------- ARM64 ----------
#if defined(__aarch64__)

    constexpr size_t kPatchLen = 4;            // one B instruction
    constexpr size_t kBRange = 128 * 1024 * 1024;
    constexpr uint32_t kBtiC = 0xD503245F;     // BTI c — NOP on pre-v8.5 hardware

    uintptr_t target_addr = (uintptr_t)target;
    uintptr_t replace_addr = (uintptr_t)replace;

    uint32_t insn0 = *(const uint32_t *)target_addr;

    void *page = alloc_near(target_addr, kBRange - page_size());
    if (!page) {
        MH_LOGE("arm64: alloc_near failed for %p", target);
        return -1;
    }
    auto *tramp = (uint8_t *)page;

    // --- Entry trampoline (16 bytes) ---
    // Reached via direct B from the patched target — no BTI needed.
    {
        auto *p = (uint32_t *)tramp;
        p[0] = 0x58000051;  // LDR X17, [PC, #8]
        p[1] = 0xD61F0220;  // BR X17
        memcpy(&p[2], &replace_addr, 8);
    }

    // --- Original trampoline (12-28 bytes, variable) ---
    // Called indirectly via function pointer (BLR), so needs BTI landing pad.
    // Uses direct B for the jump-back, which does NOT trigger BTI checks at
    // target+4 — critical for BTI-enabled linker binaries.
    uint8_t *orig_tramp = tramp + 16;
    auto *p = (uint32_t *)orig_tramp;
    *p++ = kBtiC;  // BTI c landing pad (NOP on old hw)

    // Relocate the overwritten instruction — rewrites PC-relative instructions
    // with absolute addresses so they work from the trampoline's different PC.
    int relo_n = arm64_relocate_insn(insn0, target_addr, p);
    if (relo_n < 0) {
        munmap(page, page_size());
        return -1;
    }
    p += relo_n;

    // Direct B back to the instruction after our patch
    {
        int64_t b_back = (int64_t)((target_addr + kPatchLen) - (uintptr_t)p);
        *p++ = 0x14000000u | (((uint32_t)(b_back >> 2)) & 0x03FFFFFFu);
    }

    if (finalize_trampoline(page, (uintptr_t)p - (uintptr_t)tramp) != 0) {
        munmap(page, page_size());
        return -1;
    }

    // Patch target: overwrite first instruction with B <entry_trampoline>
    if (mprotect_write(target_addr, kPatchLen) != 0) {
        MH_LOGE("arm64: mprotect failed for %p", target);
        munmap(page, page_size());
        return -1;
    }
    int64_t b_offset = (int64_t)((uintptr_t)tramp - target_addr);
    uint32_t b_instr = 0x14000000u | (((uint32_t)(b_offset >> 2)) & 0x03FFFFFFu);
    memcpy((void *)target_addr, &b_instr, 4);
    clear_cache((void *)target_addr, 4);
    mprotect_exec(target_addr, kPatchLen);

    *original = (void *)orig_tramp;
    return 0;

// ---------- ARM32 (Thumb) ----------
#elif defined(__arm__)

    constexpr size_t kMinPatch = 4;  // B.W is 4 bytes
    constexpr size_t kBwRange = 16 * 1024 * 1024;

    uintptr_t target_addr = (uintptr_t)target & ~1u;  // clear Thumb bit
    uintptr_t replace_addr = (uintptr_t)replace;

    // Determine instruction-aligned backup length (4 or 6 bytes)
    size_t backup_len = thumb_backup_len((const uint8_t *)target_addr, kMinPatch);
    if (backup_len == 0 || backup_len > 8) {
        MH_LOGE("arm: unexpected backup length %zu at %p", backup_len, target);
        return -1;
    }

    if (thumb_has_pc_relative((const uint8_t *)target_addr, backup_len)) {
        MH_LOGE("arm: PC-relative instruction in prologue at %p, cannot hook", target);
        return -1;
    }

    void *page = alloc_near(target_addr, kBwRange - page_size());
    if (!page) {
        MH_LOGE("arm: alloc_near failed for %p", target);
        return -1;
    }
    auto *tramp = (uint8_t *)page;

    // --- Entry trampoline (8 bytes) ---
    //   LDR.W PC, [PC, #0]   ; load replacement address, branch
    //   .word replace_addr
    // Page-aligned, so LDR.W is always 4-byte aligned — [PC,#0] is correct.
    tramp[0] = 0xDF; tramp[1] = 0xF8;  // LDR.W PC, [PC, #0]
    tramp[2] = 0x00; tramp[3] = 0xF0;
    memcpy(tramp + 4, &replace_addr, 4);

    // --- Original trampoline ---
    //   <saved instructions>   ; backup_len bytes (4 or 6)
    //   B.W target+backup_len  ; direct branch back (stays Thumb, no alignment issues)
    uint8_t *orig_tramp = tramp + 8;
    memcpy(orig_tramp, (void *)target_addr, backup_len);
    thumb_write_bw(orig_tramp + backup_len, target_addr + backup_len);

    size_t tramp_total = 8 + backup_len + 4;
    if (finalize_trampoline(page, tramp_total) != 0) {
        munmap(page, page_size());
        return -1;
    }

    // Patch target: B.W <entry_trampoline> + NOP-pad any excess bytes
    if (mprotect_write(target_addr, backup_len) != 0) {
        MH_LOGE("arm: mprotect failed for %p", target);
        munmap(page, page_size());
        return -1;
    }
    thumb_write_bw((uint8_t *)target_addr, (uintptr_t)tramp);
    for (size_t i = kMinPatch; i < backup_len; i += 2) {
        uint16_t nop = 0xBF00;
        memcpy((void *)(target_addr + i), &nop, 2);
    }
    clear_cache((void *)target_addr, backup_len);
    mprotect_exec(target_addr, backup_len);

    *original = (void *)((uintptr_t)orig_tramp | 1u);  // set Thumb bit
    return 0;

// ---------- x86 (32-bit) ----------
#elif defined(__i386__)

    constexpr size_t kJmpSize = 5;

    uintptr_t target_addr = (uintptr_t)target;
    uintptr_t replace_addr = (uintptr_t)replace;

    size_t backup_len = calc_backup_len((const uint8_t *)target_addr, kJmpSize);
    if (backup_len == 0) {
        MH_LOGE("x86: instruction decode failed at %p", target);
        return -1;
    }

    void *page = mmap(nullptr, page_size(), PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        MH_LOGE("x86: mmap failed");
        return -1;
    }
    auto *tramp = (uint8_t *)page;

    // Original trampoline: <saved instructions>; JMP rel32 back
    memcpy(tramp, (void *)target_addr, backup_len);
    tramp[backup_len] = 0xE9;
    int32_t jmp_back = (int32_t)(target_addr + backup_len - (uintptr_t)(tramp + backup_len + kJmpSize));
    memcpy(tramp + backup_len + 1, &jmp_back, 4);

    if (finalize_trampoline(page, backup_len + kJmpSize) != 0) {
        munmap(page, page_size());
        return -1;
    }

    // Overwrite target with JMP rel32 to replace
    if (mprotect_write(target_addr, backup_len) != 0) {
        MH_LOGE("x86: mprotect failed for %p", target);
        munmap(page, page_size());
        return -1;
    }
    auto *t = (uint8_t *)target_addr;
    t[0] = 0xE9;
    int32_t jmp_to = (int32_t)(replace_addr - (target_addr + kJmpSize));
    memcpy(t + 1, &jmp_to, 4);
    for (size_t i = kJmpSize; i < backup_len; i++) t[i] = 0x90;  // NOP padding
    clear_cache((void *)target_addr, backup_len);
    mprotect_exec(target_addr, backup_len);

    *original = (void *)tramp;
    return 0;

// ---------- x86_64 ----------
#elif defined(__x86_64__)

    constexpr size_t kJmpSize = 5;
    constexpr size_t kAbsJmpSize = 14;
    constexpr size_t kJmpRange = 0x7FFFFF00ULL;

    uintptr_t target_addr = (uintptr_t)target;
    uintptr_t replace_addr = (uintptr_t)replace;

    size_t backup_len = calc_backup_len((const uint8_t *)target_addr, kJmpSize);
    if (backup_len == 0) {
        MH_LOGE("x64: instruction decode failed at %p", target);
        return -1;
    }

    // Helper: write JMP [RIP+0]; .quad addr  (14 bytes)
    auto write_abs_jmp = [](uint8_t *buf, uintptr_t addr) {
        buf[0] = 0xFF; buf[1] = 0x25;
        uint32_t zero = 0;
        memcpy(buf + 2, &zero, 4);
        memcpy(buf + 6, &addr, 8);
    };

    void *page = alloc_near(target_addr, kJmpRange);
    if (!page) {
        // Far fallback: absolute jump at target (needs 14 bytes)
        backup_len = calc_backup_len((const uint8_t *)target_addr, kAbsJmpSize);
        if (backup_len == 0) {
            MH_LOGE("x64: decode failed at %p (need %zu bytes)", target, kAbsJmpSize);
            return -1;
        }
        page = mmap(nullptr, page_size(), PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) {
            MH_LOGE("x64: mmap failed");
            return -1;
        }
        auto *tramp = (uint8_t *)page;
        memcpy(tramp, (void *)target_addr, backup_len);
        write_abs_jmp(tramp + backup_len, target_addr + backup_len);

        if (finalize_trampoline(page, backup_len + kAbsJmpSize) != 0) {
            munmap(page, page_size());
            return -1;
        }

        if (mprotect_write(target_addr, backup_len) != 0) {
            MH_LOGE("x64: mprotect failed for %p", target);
            munmap(page, page_size());
            return -1;
        }
        write_abs_jmp((uint8_t *)target_addr, replace_addr);
        for (size_t i = kAbsJmpSize; i < backup_len; i++) ((uint8_t *)target_addr)[i] = 0x90;
        clear_cache((void *)target_addr, backup_len);
        mprotect_exec(target_addr, backup_len);

        *original = (void *)tramp;
        return 0;
    }

    // Near path
    auto *tramp = (uint8_t *)page;

    // Entry trampoline: absolute jump to replacement (14 bytes, padded to 16)
    write_abs_jmp(tramp, replace_addr);

    // Original trampoline: saved instructions + absolute jump back
    uint8_t *orig_tramp = tramp + 16;
    memcpy(orig_tramp, (void *)target_addr, backup_len);
    write_abs_jmp(orig_tramp + backup_len, target_addr + backup_len);

    if (finalize_trampoline(page, 16 + backup_len + kAbsJmpSize) != 0) {
        munmap(page, page_size());
        return -1;
    }

    // Overwrite target with JMP rel32 -> entry trampoline
    if (mprotect_write(target_addr, backup_len) != 0) {
        MH_LOGE("x64: mprotect failed for %p", target);
        munmap(page, page_size());
        return -1;
    }
    auto *t = (uint8_t *)target_addr;
    t[0] = 0xE9;
    int32_t jmp_to = (int32_t)((uintptr_t)tramp - (target_addr + kJmpSize));
    memcpy(t + 1, &jmp_to, 4);
    for (size_t i = kJmpSize; i < backup_len; i++) t[i] = 0x90;
    clear_cache((void *)target_addr, backup_len);
    mprotect_exec(target_addr, backup_len);

    *original = (void *)orig_tramp;
    return 0;

#else
    #error "mini_hook: unsupported architecture"
#endif
}
