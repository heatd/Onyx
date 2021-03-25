/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_RISCV_PLATFORM_IRQ_H
#define _ONYX_RISCV_PLATFORM_IRQ_H

#include <onyx/registers.h>

// TODO: Correct values
#define NR_IRQ 				223
#define PCI_MSI_BASE_ADDRESS 		0xFEE00000
#define PCI_MSI_APIC_ID_SHIFT		12
#define PCI_MSI_REDIRECTION_HINT	(1 << 3)

#define CPU_FLAGS_NO_IRQ 0

struct irq_context
{
	unsigned int irq_nr;
	registers_t *registers;
};

void softirq_try_handle(void);

static inline unsigned long irq_save_and_disable()
{
	return 0;
}

static inline void irq_restore(unsigned long flags)
{
}

static inline void irq_enable(void)
{

}

static inline void irq_disable(void)
{

}

inline bool irq_is_disabled()
{
	return false;
}

#endif
