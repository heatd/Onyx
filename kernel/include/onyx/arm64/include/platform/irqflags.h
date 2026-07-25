/*
 * Copyright (c) 2021 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_ARM64_PLATFORM_IRQF_H
#define _ONYX_ARM64_PLATFORM_IRQF_H

#include <onyx/intrinsics.h>


#define CPU_FLAGS_NO_IRQ (1 << 7)

static inline void arch_irq_disable(void)
{
    __asm__ __volatile__("msr daifset, #3" ::: "memory");
}

static inline unsigned long arch_irq_save_and_disable(void)
{
    unsigned long flags = mrs("daif");
    arch_irq_disable();
    return flags;
}

static inline void arch_irq_restore(unsigned long flags)
{
    msr("daif", flags);
}

static inline void arch_irq_enable()
{
    __asm__ __volatile__("msr daifclr, #3" ::: "memory");
}

static inline bool arch_irq_is_disabled()
{
    unsigned long flags = mrs("daif");
    return flags & CPU_FLAGS_NO_IRQ;
}

#endif
