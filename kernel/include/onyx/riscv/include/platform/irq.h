/*
 * Copyright (c) 2021 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_RISCV_PLATFORM_IRQ_H
#define _ONYX_RISCV_PLATFORM_IRQ_H

#include <onyx/registers.h>
#include <onyx/riscv/intrinsics.h>

// TODO: Correct values
#define NR_IRQ                   223
#define PCI_MSI_BASE_ADDRESS     0xFEE00000
#define PCI_MSI_APIC_ID_SHIFT    12
#define PCI_MSI_REDIRECTION_HINT (1 << 3)

#define CPU_FLAGS_NO_IRQ 0

struct irq_context
{
    unsigned int irq_nr;
    registers_t *registers;
};

void softirq_try_handle(void);

static inline unsigned long irq_save_and_disable()
{
    unsigned long status = riscv_read_csr(RISCV_SSTATUS);
    riscv_clear_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
    return status;
}

static inline void irq_restore(unsigned long flags)
{
    if (flags & RISCV_SSTATUS_SIE)
        riscv_or_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
    else
        riscv_clear_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
}

static inline void irq_enable(void)
{
    riscv_or_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
}

static inline void irq_disable(void)
{
    riscv_clear_csr(RISCV_SSTATUS, RISCV_SSTATUS_SIE);
}

inline bool irq_is_disabled()
{
    unsigned long status = riscv_read_csr(RISCV_SSTATUS);
    return !(status & RISCV_SSTATUS_SIE);
}

#endif
