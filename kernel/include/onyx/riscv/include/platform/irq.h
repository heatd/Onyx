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

#include <platform/irqflags.h>

// TODO: Correct values
#define NR_IRQ                   223
#define PCI_MSI_BASE_ADDRESS     0xFEE00000
#define PCI_MSI_APIC_ID_SHIFT    12
#define PCI_MSI_REDIRECTION_HINT (1 << 3)

struct irq_context
{
    unsigned int irq_nr;
    registers_t *registers;
};

void softirq_try_handle(void);

#endif
