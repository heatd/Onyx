/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _X86_IRQ_H
#define _X86_IRQ_H

#define NR_IRQ 				221
#define PCI_MSI_BASE_ADDRESS 		0xFEE00000
#define PCI_MSI_APIC_ID_SHIFT		12
#define PCI_MSI_REDIRECTION_HINT	(1 << 3)

struct irq_context
{
	registers_t *registers;
};

#endif
