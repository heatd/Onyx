/*
 * Copyright (c) 2023 Pedro Falcato
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_UAPI_SIGNAL_H
#define _ONYX_UAPI_SIGNAL_H

#include <onyx/types.h>

typedef unsigned long greg_t;
typedef unsigned long gregset_t[34];

typedef struct
{
    __uint128_t vregs[32];
    unsigned int fpsr;
    unsigned int fpcr;
} fpregset_t;

typedef struct sigcontext
{
    unsigned long fault_address;
    unsigned long regs[31];
    unsigned long sp, pc, pstate;
    __u8 __reserved[4096] __attribute__((aligned(16)));
} mcontext_t;

#define FPSIMD_MAGIC 0x46508001
#define ESR_MAGIC    0x45535201
#define EXTRA_MAGIC  0x45585401
#define SVE_MAGIC    0x53564501

struct _aarch64_ctx
{
    unsigned int magic;
    unsigned int size;
};

struct fpsimd_context
{
    struct _aarch64_ctx head;
    unsigned int fpsr;
    unsigned int fpcr;
    __uint128_t vregs[32];
};

struct esr_context
{
    struct _aarch64_ctx head;
    unsigned long esr;
};

struct extra_context
{
    struct _aarch64_ctx head;
    unsigned long datap;
    unsigned int size;
    unsigned int __reserved[3];
};

struct sve_context
{
    struct _aarch64_ctx head;
    unsigned short vl;
    unsigned short __reserved[3];
};

#define SVE_VQ_BYTES          16
#define SVE_VQ_MIN            1
#define SVE_VQ_MAX            512
#define SVE_VL_MIN            (SVE_VQ_MIN * SVE_VQ_BYTES)
#define SVE_VL_MAX            (SVE_VQ_MAX * SVE_VQ_BYTES)
#define SVE_NUM_ZREGS         32
#define SVE_NUM_PREGS         16
#define sve_vl_valid(vl)      ((vl) % SVE_VQ_BYTES == 0 && (vl) >= SVE_VL_MIN && (vl) <= SVE_VL_MAX)
#define sve_vq_from_vl(vl)    ((vl) / SVE_VQ_BYTES)
#define sve_vl_from_vq(vq)    ((vq) *SVE_VQ_BYTES)
#define SVE_SIG_ZREG_SIZE(vq) ((unsigned) (vq) *SVE_VQ_BYTES)
#define SVE_SIG_PREG_SIZE(vq) ((unsigned) (vq) * (SVE_VQ_BYTES / 8))
#define SVE_SIG_FFR_SIZE(vq)  SVE_SIG_PREG_SIZE(vq)
#define SVE_SIG_REGS_OFFSET \
    ((sizeof(struct sve_context) + (SVE_VQ_BYTES - 1)) / SVE_VQ_BYTES * SVE_VQ_BYTES)
#define SVE_SIG_ZREGS_OFFSET       SVE_SIG_REGS_OFFSET
#define SVE_SIG_ZREG_OFFSET(vq, n) (SVE_SIG_ZREGS_OFFSET + SVE_SIG_ZREG_SIZE(vq) * (n))
#define SVE_SIG_ZREGS_SIZE(vq)     (SVE_SIG_ZREG_OFFSET(vq, SVE_NUM_ZREGS) - SVE_SIG_ZREGS_OFFSET)
#define SVE_SIG_PREGS_OFFSET(vq)   (SVE_SIG_ZREGS_OFFSET + SVE_SIG_ZREGS_SIZE(vq))
#define SVE_SIG_PREG_OFFSET(vq, n) (SVE_SIG_PREGS_OFFSET(vq) + SVE_SIG_PREG_SIZE(vq) * (n))
#define SVE_SIG_PREGS_SIZE(vq)     (SVE_SIG_PREG_OFFSET(vq, SVE_NUM_PREGS) - SVE_SIG_PREGS_OFFSET(vq))
#define SVE_SIG_FFR_OFFSET(vq)     (SVE_SIG_PREGS_OFFSET(vq) + SVE_SIG_PREGS_SIZE(vq))
#define SVE_SIG_REGS_SIZE(vq)      (SVE_SIG_FFR_OFFSET(vq) + SVE_SIG_FFR_SIZE(vq) - SVE_SIG_REGS_OFFSET)
#define SVE_SIG_CONTEXT_SIZE(vq)   (SVE_SIG_REGS_OFFSET + SVE_SIG_REGS_SIZE(vq))

/* Include generic signal definitions, after our struct code */
#include <uapi/signal-generic.h>

#endif
