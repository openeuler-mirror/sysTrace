/* libunwind - a platform-independent unwind library
   Copyright (C) 2001-2004 Hewlett-Packard Co
        Contributed by David Mosberger-Tang <davidm@hpl.hp.com>
   Copyright (C) 2013 Linaro Limited
   Copyright 2022 Blackberry Limited

This file is part of libunwind.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#ifndef LIBUNWIND_H
#define LIBUNWIND_H

#if defined(__cplusplus) || defined(c_plusplus)
extern "C"
{
#endif

#include <inttypes.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <ucontext.h>

#ifndef UNW_EMPTY_STRUCT
#define UNW_EMPTY_STRUCT uint8_t unused;
#endif

#define UNW_TARGET aarch64
#define UNW_TARGET_AARCH64 1

#define _U_TDEP_QP_TRUE 0 /* see libunwind-dynamic.h  */

    /* This needs to be big enough to accommodate "struct cursor", while
       leaving some slack for future expansion.  Changing this value will
       require recompiling all users of this library.  Stack allocation is
       relatively cheap and unwind-state copying is relatively rare, so we
       want to err on making it rather too big than too small.

       Calculation is regs used (64 + 34) * 2 + 40 (bytes of rest of
       cursor) + padding
    */

#define UNW_TDEP_CURSOR_LEN 250

    typedef uint64_t unw_word_t;
    typedef int64_t unw_sword_t;

    typedef long double unw_tdep_fpreg_t;

#define UNW_WORD_MAX UINT64_MAX

    typedef struct
    {
        /* no aarch64-specific auxiliary proc-info */
        UNW_EMPTY_STRUCT
    } unw_tdep_proc_info_t;

    typedef enum
    {
        /* 64-bit general registers.  */
        UNW_AARCH64_X0,
        UNW_AARCH64_X1,
        UNW_AARCH64_X2,
        UNW_AARCH64_X3,
        UNW_AARCH64_X4,
        UNW_AARCH64_X5,
        UNW_AARCH64_X6,
        UNW_AARCH64_X7,
        UNW_AARCH64_X8,

        /* Temporary registers.  */
        UNW_AARCH64_X9,
        UNW_AARCH64_X10,
        UNW_AARCH64_X11,
        UNW_AARCH64_X12,
        UNW_AARCH64_X13,
        UNW_AARCH64_X14,
        UNW_AARCH64_X15,

        /* Intra-procedure-call temporary registers.  */
        UNW_AARCH64_X16,
        UNW_AARCH64_X17,

        /* Callee-saved registers.  */
        UNW_AARCH64_X18,
        UNW_AARCH64_X19,
        UNW_AARCH64_X20,
        UNW_AARCH64_X21,
        UNW_AARCH64_X22,
        UNW_AARCH64_X23,
        UNW_AARCH64_X24,
        UNW_AARCH64_X25,
        UNW_AARCH64_X26,
        UNW_AARCH64_X27,
        UNW_AARCH64_X28,

        /* 64-bit frame pointer.  */
        UNW_AARCH64_X29,

        /* 64-bit link register.  */
        UNW_AARCH64_X30,

        /* 64-bit stack pointer.  */
        UNW_AARCH64_SP = 31,
        UNW_AARCH64_PC,
        UNW_AARCH64_PSTATE,

        /* Pseudo-register */
        UNW_AARCH64_RA_SIGN_STATE = 34,

        /* SVE Vector Granule pseudo register */
        UNW_AARCH64_VG = 46,

        /* 128-bit FP/Advanced SIMD registers.  */
        UNW_AARCH64_V0 = 64,
        UNW_AARCH64_V1,
        UNW_AARCH64_V2,
        UNW_AARCH64_V3,
        UNW_AARCH64_V4,
        UNW_AARCH64_V5,
        UNW_AARCH64_V6,
        UNW_AARCH64_V7,
        UNW_AARCH64_V8,
        UNW_AARCH64_V9,
        UNW_AARCH64_V10,
        UNW_AARCH64_V11,
        UNW_AARCH64_V12,
        UNW_AARCH64_V13,
        UNW_AARCH64_V14,
        UNW_AARCH64_V15,
        UNW_AARCH64_V16,
        UNW_AARCH64_V17,
        UNW_AARCH64_V18,
        UNW_AARCH64_V19,
        UNW_AARCH64_V20,
        UNW_AARCH64_V21,
        UNW_AARCH64_V22,
        UNW_AARCH64_V23,
        UNW_AARCH64_V24,
        UNW_AARCH64_V25,
        UNW_AARCH64_V26,
        UNW_AARCH64_V27,
        UNW_AARCH64_V28,
        UNW_AARCH64_V29,
        UNW_AARCH64_V30,
        UNW_AARCH64_V31,

        UNW_AARCH64_FPSR,
        UNW_AARCH64_FPCR,

        /* For AArch64, the CFA is the value of SP (x31) at the call site of the
           previous frame.  */
        UNW_AARCH64_CFA = UNW_AARCH64_SP,

        UNW_TDEP_LAST_REG = UNW_AARCH64_FPCR,

        UNW_TDEP_IP = UNW_AARCH64_X30,
        UNW_TDEP_SP = UNW_AARCH64_SP,
        UNW_TDEP_EH = UNW_AARCH64_X0

    } aarch64_regnum_t;

/* Use R0 through R3 to pass exception handling information.  */
#define UNW_TDEP_NUM_EH_REGS 4

    typedef struct unw_tdep_save_loc
    {
        /* Additional target-dependent info on a save location.  */
        UNW_EMPTY_STRUCT
    } unw_tdep_save_loc_t;

#ifdef __linux__
    /* On AArch64, we can directly use ucontext_t as the unwind context,
     * however, the __reserved struct is quite large: tune it down to only
     * the necessary used fields.  */

    struct unw_sigcontext
    {
        uint64_t fault_address;
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
        alignas(16) uint8_t __reserved[(66 * 8)];
    };

    typedef struct
    {
        unsigned long uc_flags;
        struct ucontext *uc_link;
        stack_t uc_stack;
#ifndef __ANDROID__
        sigset_t uc_sigmask;
#else
        union
        {
            sigset_t uc_sigmask;
            sigset64_t uc_sigmask64;
        };
        char __padding[128 - sizeof(sigset_t)];
#endif
        struct unw_sigcontext uc_mcontext;
    } unw_tdep_context_t;

    typedef struct
    {
        uint32_t _ctx_magic;
        uint32_t _ctx_size;
        uint32_t fpsr;
        uint32_t fpcr;
        uint64_t vregs[64];
    } unw_fpsimd_context_t;
#else
/* On AArch64, we can directly use ucontext_t as the unwind context.  */
typedef ucontext_t unw_tdep_context_t;
#endif

#include "libunwind-common.h"
#include "libunwind-dynamic.h"

#if defined(__FreeBSD__)
#define UNW_BASE                                                               \
    register uint64_t unw_base __asm__("x0") =                                 \
        (uint64_t)unw_ctx->uc_mcontext.mc_gpregs.gp_x;
#elif defined(__QNX__)
#define UNW_BASE                                                               \
    register uint64_t unw_base __asm__("x0") =                                 \
        (uint64_t)unw_ctx->uc_mcontext.cpu.gpr;
#else
#define UNW_BASE                                                               \
    register uint64_t unw_base __asm__("x0") =                                 \
        (uint64_t)unw_ctx->uc_mcontext.regs;
#endif

#define unw_tdep_getcontext(uc)                                                \
    ({                                                                         \
        unw_tdep_context_t *unw_ctx = (uc);                                    \
        UNW_BASE                                                               \
        __asm__ __volatile__("stp x0, x1, [%[base], #0]\n"                     \
                             "stp x2, x3, [%[base], #16]\n"                    \
                             "stp x4, x5, [%[base], #32]\n"                    \
                             "stp x6, x7, [%[base], #48]\n"                    \
                             "stp x8, x9, [%[base], #64]\n"                    \
                             "stp x10, x11, [%[base], #80]\n"                  \
                             "stp x12, x13, [%[base], #96]\n"                  \
                             "stp x14, x15, [%[base], #112]\n"                 \
                             "stp x16, x17, [%[base], #128]\n"                 \
                             "stp x18, x19, [%[base], #144]\n"                 \
                             "stp x20, x21, [%[base], #160]\n"                 \
                             "stp x22, x23, [%[base], #176]\n"                 \
                             "stp x24, x25, [%[base], #192]\n"                 \
                             "stp x26, x27, [%[base], #208]\n"                 \
                             "stp x28, x29, [%[base], #224]\n"                 \
                             "mov x1, sp\n"                                    \
                             "stp x30, x1, [%[base], #240]\n"                  \
                             "adr x1, ret%=\n"                                 \
                             "str x1, [%[base], #256]\n"                       \
                             "mov %[base], #0\n"                               \
                             "ret%=:\n"                                        \
                             : [base] "+r"(unw_base)                           \
                             :                                                 \
                             : "x1", "memory");                                \
        (int)unw_base;                                                         \
    })
#define unw_tdep_is_fpreg UNW_ARCH_OBJ(is_fpreg)

    extern int unw_tdep_is_fpreg(int);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* LIBUNWIND_H */
