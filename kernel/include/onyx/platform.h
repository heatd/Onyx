/*
 * Copyright (c) 2017 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_PLATFORM_H
#define _ONYX_PLATFORM_H
#include <stdbool.h>

#include <onyx/irq.h>

#include <pci/pci-msi.h>

int platform_allocate_msi_interrupts(unsigned int num_vectors, bool addr64,
                                     struct pci_msi_data *data, unsigned int flags,
                                     unsigned int target_cpu);

int platform_install_irq(unsigned int irqn, struct interrupt_handler *h);
void platform_mask_irq(unsigned int irq);

void platform_init_acpi(void);

bool platform_has_msi();

#endif
