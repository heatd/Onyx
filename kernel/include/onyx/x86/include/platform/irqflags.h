/*
 * Copyright (c) 2018 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _X86_PLATFORM_IRQFLAGS_H
#define _X86_PLATFORM_IRQFLAGS_H

#include <onyx/x86/eflags.h>

static inline unsigned long arch_save_flags(void)
{
    unsigned long flags;
    __asm__ __volatile__("pushf; pop %0" : "=rm"(flags)::"memory");
    return flags;
}

static inline void arch_irq_disable(void)
{
    __asm__ __volatile__("cli");
}

static inline unsigned long arch_irq_save_and_disable(void)
{
    unsigned long flags = arch_save_flags();
    arch_irq_disable();
    return flags;
}

static inline void arch_irq_enable()
{
    __asm__ __volatile__("sti");
}

#define CPU_FLAGS_NO_IRQ (0)

static inline bool arch_irq_is_disabled()
{
    return !(arch_save_flags() & EFLAGS_INT_ENABLED);
}

static inline void arch_irq_restore(unsigned long flags)
{
    if (flags & EFLAGS_INT_ENABLED)
        arch_irq_enable();
}

#endif
