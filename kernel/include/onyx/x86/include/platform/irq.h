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

#include <platform/irqflags.h>

#define NR_IRQ                   223
#define PCI_MSI_BASE_ADDRESS     0xFEE00000
#define PCI_MSI_APIC_ID_SHIFT    12
#define PCI_MSI_REDIRECTION_HINT (1 << 3)

struct irq_context
{
    unsigned int irq_nr;
    registers_t *registers;
};

#endif
