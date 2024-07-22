/*
 * Copyright (c) 2018 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _X86_IRQ_H
#define _X86_IRQ_H

#include <onyx/registers.h>
#include <onyx/x86/eflags.h>

#define NR_IRQ                   223
#define PCI_MSI_BASE_ADDRESS     0xFEE00000
#define PCI_MSI_APIC_ID_SHIFT    12
#define PCI_MSI_REDIRECTION_HINT (1 << 3)

struct irq_context
{
    unsigned int irq_nr;
    registers_t *registers;
};

#ifdef __cplusplus
extern "C"
{
#endif

static inline unsigned long x86_save_flags(void)
{
    unsigned long flags;
    __asm__ __volatile__("pushf; pop %0" : "=rm"(flags)::"memory");
    return flags;
}

static inline void irq_disable(void)
{
    __asm__ __volatile__("cli");
}

static inline void irq_enable()
{
    __asm__ __volatile__("sti");
}

static inline unsigned long irq_save_and_disable()
{
    unsigned long old = x86_save_flags();
    irq_disable();

    return old;
}

#define CPU_FLAGS_NO_IRQ (0)

static inline bool irq_is_disabled()
{
    return !(x86_save_flags() & EFLAGS_INT_ENABLED);
}

static inline void irq_restore(unsigned long flags)
{
    if (flags & EFLAGS_INT_ENABLED)
    {
        irq_enable();
    }
}

#ifdef __cplusplus
}
#endif

#endif
