/*
 * Copyright (c) 2021 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_RISCV_PLATFORM_IRQF_H
#define _ONYX_RISCV_PLATFORM_IRQF_H

#include <onyx/riscv/intrinsics.h>

#define CPU_FLAGS_NO_IRQ 0

static inline unsigned long arch_irq_save_and_disable()
{
    unsigned long status = riscv_read_csr(RISCV_SSTATUS);
    riscv_clear_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
    return status;
}

static inline void arch_irq_restore(unsigned long flags)
{
    if (flags & RISCV_SSTATUS_SIE)
        riscv_or_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
    else
        riscv_clear_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
}

static inline void arch_irq_enable(void)
{
    riscv_or_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
}

static inline void arch_irq_disable(void)
{
    riscv_clear_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
}

static inline bool arch_irq_is_disabled()
{
    unsigned long status = riscv_read_csr(RISCV_SSTATUS);
    return !(status & RISCV_SSTATUS_SIE);
}

#endif
