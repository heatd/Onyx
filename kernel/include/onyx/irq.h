/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_IRQ_H
#define _ONYX_IRQ_H

#include <stdbool.h>
#include <stdint.h>

#include <onyx/registers.h>
#include <onyx/spinlock.h>

#ifdef __x86_64__
#include <onyx/x86/apic.h>
#endif

#include <platform/irq.h>

#define IRQ_HANDLED   0
#define IRQ_UNHANDLED -1

#define IRQ_FLAG_REGULAR 0
#define IRQ_FLAG_LOW     (1 << 0)
#define IRQ_FLAG_LEVEL   (1 << 1)

typedef int irqstatus_t;
typedef irqstatus_t (*irq_t)(struct irq_context *context, void *cookie);

struct interrupt_handler
{
    irq_t handler;
    struct device *device;
    void *cookie;
    unsigned long handled_irqs;
    unsigned int flags;
    struct interrupt_handler *next;
};

struct irqstats
{
    unsigned long handled_irqs;
    unsigned long spurious;
};

struct irq_line
{
    struct interrupt_handler *irq_handlers;
    /* Here to stop race conditions with uninstalling and installing irq handlers */
    struct spinlock list_lock;
    struct irqstats stats;
};

extern bool in_irq;

__always_inline __nocov bool is_in_interrupt()
{
    return get_per_cpu(in_irq);
}

void dispatch_irq(unsigned int irq, struct irq_context *context);
int install_irq(unsigned int irq, irq_t handler, struct device *device, unsigned int flags,
                void *cookie);
void free_irq(unsigned int irq, struct device *device);
void irq_init(void);

#endif
