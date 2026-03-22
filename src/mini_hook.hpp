// mini_hook - Minimal inline hook for function entry points
// Header-only. Supports: ARM64, ARM32 (Thumb), x86, x86_64
//
// Architecture overview:
//   1. Allocate an executable page near the target function
//   2. Write an "entry trampoline" that jumps to the replacement function
//   3. Write an "original trampoline" that executes saved instructions then jumps back
//   4. Overwrite target's first N bytes with a relative branch to the entry trampoline
//
// Limitations:
//   - Only hooks function entry points (assumes prologue instructions are not PC-relative)
//   - Not suitable for hooking arbitrary instruction addresses
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

inline int mprotect_rwx(uintptr_t addr, size_t len) {
    uintptr_t start = page_align(addr);
    uintptr_t end = page_align(addr + len - 1 + page_size());
    return mprotect((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC);
}

inline void clear_cache(void *addr, size_t len) {
    __builtin___clear_cache((char *)addr, (char *)addr + len);
}

// Allocate an executable page near `target` (within `range` bytes).
inline void *alloc_near(uintptr_t target, size_t range) {
    uintptr_t ps = page_size();
    int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;

    for (uintptr_t offset = ps; offset < range; offset += ps) {
        if (target > offset) {
            uintptr_t hint = page_align(target - offset);
            void *p = mmap((void *)hint, ps, prot, flags, -1, 0);
            if (p != MAP_FAILED) {
                if ((uintptr_t)p >= target - range && (uintptr_t)p <= target + range)
                    return p;
                munmap(p, ps);
            }
        }
        {
            uintptr_t hint = page_align(target + offset);
            void *p = mmap((void *)hint, ps, prot, flags, -1, 0);
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
    else if (op == 0xF6) { has_modrm = true; imm_size = 1; }             // TEST/NOT/NEG r/m8
    else if (op == 0xF7) { has_modrm = true; imm_size = has_prefix_66 ? 2 : 4; } // TEST/NOT/NEG r/m
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

    constexpr size_t kBackupLen = 4;
    constexpr size_t kBRange = 128 * 1024 * 1024;

    uintptr_t target_addr = (uintptr_t)target;
    uintptr_t replace_addr = (uintptr_t)replace;

    void *page = alloc_near(target_addr, kBRange - page_size());
    if (!page) {
        MH_LOGE("arm64: failed to allocate near page for %p", target);
        return -1;
    }
    auto *tramp = (uint8_t *)page;

    // Entry trampoline: LDR X17, #8; BR X17; .quad replace_addr
    {
        auto *p = (uint32_t *)tramp;
        p[0] = 0x58000051;  // LDR X17, [PC, #8]
        p[1] = 0xD61F0220;  // BR X17
        memcpy(&p[2], &replace_addr, 8);
    }

    // Original trampoline: <saved instr>; LDR X17, #8; BR X17; .quad (target+4)
    uint8_t *orig_tramp = tramp + 16;
    memcpy(orig_tramp, (void *)target_addr, kBackupLen);
    {
        auto *p = (uint32_t *)(orig_tramp + kBackupLen);
        uintptr_t ret_addr = target_addr + kBackupLen;
        p[0] = 0x58000051;
        p[1] = 0xD61F0220;
        memcpy(&p[2], &ret_addr, 8);
    }
    clear_cache(page, 36);

    // Overwrite target with B <entry_trampoline>
    if (mprotect_rwx(target_addr, kBackupLen) != 0) {
        MH_LOGE("arm64: mprotect failed for %p", target);
        munmap(page, page_size());
        return -1;
    }
    int64_t b_offset = (int64_t)((uintptr_t)tramp - target_addr);
    uint32_t b_instr = 0x14000000u | (((uint32_t)(b_offset >> 2)) & 0x03FFFFFFu);
    memcpy((void *)target_addr, &b_instr, 4);
    clear_cache((void *)target_addr, 4);

    *original = (void *)orig_tramp;
    return 0;

// ---------- ARM32 (Thumb) ----------
#elif defined(__arm__)

    constexpr size_t kBackupLen = 4;
    constexpr size_t kBwRange = 16 * 1024 * 1024;

    uintptr_t target_addr = (uintptr_t)target & ~1u;  // clear Thumb bit
    uintptr_t replace_addr = (uintptr_t)replace;

    void *page = alloc_near(target_addr, kBwRange - page_size());
    if (!page) {
        MH_LOGE("arm: failed to allocate near page for %p", target);
        return -1;
    }
    auto *tramp = (uint8_t *)page;

    // Entry trampoline: LDR.W PC, [PC, #0]; .word replace_addr  (8 bytes)
    tramp[0] = 0xDF; tramp[1] = 0xF8;  // LDR.W PC, [PC, #0]
    tramp[2] = 0x00; tramp[3] = 0xF0;
    memcpy(tramp + 4, &replace_addr, 4);

    // Original trampoline: <saved instr>; LDR.W PC, [PC, #0]; .word (target+4|1)
    uint8_t *orig_tramp = tramp + 8;
    memcpy(orig_tramp, (void *)target_addr, kBackupLen);
    uintptr_t ret_addr = (target_addr + kBackupLen) | 1u;  // Thumb bit
    orig_tramp[4] = 0xDF; orig_tramp[5] = 0xF8;
    orig_tramp[6] = 0x00; orig_tramp[7] = 0xF0;
    memcpy(orig_tramp + 8, &ret_addr, 4);
    clear_cache(page, 20);

    // Overwrite target with B.W <entry_trampoline>
    if (mprotect_rwx(target_addr, kBackupLen) != 0) {
        MH_LOGE("arm: mprotect failed for %p", target);
        munmap(page, page_size());
        return -1;
    }
    {
        int32_t offset = (int32_t)(((uintptr_t)tramp | 1u) - (target_addr + 4));
        uint32_t s = (offset >> 24) & 1;
        uint32_t i1 = (offset >> 23) & 1;
        uint32_t i2 = (offset >> 22) & 1;
        uint32_t imm10 = (offset >> 12) & 0x3FF;
        uint32_t imm11 = (offset >> 1) & 0x7FF;
        uint32_t j1 = ((~i1) ^ s) & 1;
        uint32_t j2 = ((~i2) ^ s) & 1;
        uint16_t hw0 = 0xF000 | (s << 10) | imm10;
        uint16_t hw1 = 0x9000 | (j1 << 13) | (j2 << 11) | imm11;
        memcpy((void *)target_addr, &hw0, 2);
        memcpy((void *)(target_addr + 2), &hw1, 2);
    }
    clear_cache((void *)target_addr, 4);

    *original = (void *)((uintptr_t)orig_tramp | 1u);  // Thumb bit
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

    void *page = mmap(nullptr, page_size(), PROT_READ | PROT_WRITE | PROT_EXEC,
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
    clear_cache(page, backup_len + kJmpSize);

    // Overwrite target with JMP rel32 to replace
    if (mprotect_rwx(target_addr, backup_len) != 0) {
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
        // Far fallback: absolute jump at target (14 bytes)
        backup_len = calc_backup_len((const uint8_t *)target_addr, kAbsJmpSize);
        if (backup_len == 0) {
            MH_LOGE("x64: decode failed at %p (need %zu bytes)", target, kAbsJmpSize);
            return -1;
        }
        page = mmap(nullptr, page_size(), PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) {
            MH_LOGE("x64: mmap failed");
            return -1;
        }
        auto *tramp = (uint8_t *)page;
        memcpy(tramp, (void *)target_addr, backup_len);
        write_abs_jmp(tramp + backup_len, target_addr + backup_len);
        clear_cache(page, backup_len + kAbsJmpSize);

        if (mprotect_rwx(target_addr, backup_len) != 0) {
            MH_LOGE("x64: mprotect failed for %p", target);
            munmap(page, page_size());
            return -1;
        }
        write_abs_jmp((uint8_t *)target_addr, replace_addr);
        for (size_t i = kAbsJmpSize; i < backup_len; i++) ((uint8_t *)target_addr)[i] = 0x90;
        clear_cache((void *)target_addr, backup_len);

        *original = (void *)tramp;
        return 0;
    }

    // Near path
    auto *tramp = (uint8_t *)page;

    // Entry trampoline: absolute jump to replacement
    write_abs_jmp(tramp, replace_addr);

    // Original trampoline: saved instructions + absolute jump back
    uint8_t *orig_tramp = tramp + 16;
    memcpy(orig_tramp, (void *)target_addr, backup_len);
    write_abs_jmp(orig_tramp + backup_len, target_addr + backup_len);
    clear_cache(page, 16 + backup_len + kAbsJmpSize);

    // Overwrite target with JMP rel32 → entry trampoline
    if (mprotect_rwx(target_addr, backup_len) != 0) {
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

    *original = (void *)orig_tramp;
    return 0;

#else
    #error "mini_hook: unsupported architecture"
#endif
}
