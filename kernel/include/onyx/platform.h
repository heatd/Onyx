/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_PLATFORM_H
#define _KERNEL_PLATFORM_H
#include <stdbool.h>

#include <onyx/irq.h>

#include <pci/pci-msi.h>

int platform_allocate_msi_interrupts(unsigned int num_vectors, bool addr64, 
                                     struct pci_msi_data *data);

int platform_install_irq(unsigned int irqn, struct interrupt_handler *h);
void platform_mask_irq(unsigned int irq);

#endif
