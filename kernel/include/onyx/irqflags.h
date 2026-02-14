/*
 * Copyright (c) 2018 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_IRQFLAGS_H
#define _ONYX_IRQFLAGS_H

#include <linux/irqflags_lockdep.h>
#include <platform/irqflags.h>

#if CONFIG_TRACE_IRQFLAGS

// clang-format off
#ifndef _THIS_IP_
#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#endif
// clang-format on

static inline unsigned long irq_save_and_disable(void)
{
    unsigned long old = arch_irq_save_and_disable();
    if (!arch_irq_flags_disabled(old))
        lockdep_hardirqs_off(_THIS_IP_);
    return old;
}

static inline void irq_disable(void)
{
    arch_irq_disable();
    lockdep_hardirqs_off(_THIS_IP_);
}

static inline void irq_enable(void)
{
    arch_irq_enable();
    lockdep_hardirqs_on(_THIS_IP_);
}

#define CPU_FLAGS_NO_IRQ (0)

static inline void irq_restore(unsigned long flags)
{
    arch_irq_restore(flags);
    if (arch_irq_is_enabled())
        lockdep_hardirqs_on(_THIS_IP_);
}

#else

#define irq_save_and_disable() arch_irq_save_and_disable()
#define irq_disable()          arch_irq_disable()
#define irq_enable()           arch_irq_enable()
#define irq_restore(flags)     arch_irq_restore(flags)
#endif

#define irq_is_disabled() arch_irq_is_disabled()

#endif
