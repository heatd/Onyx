/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include <onyx/scheduler.h>
#include <onyx/task_switching.h>
#include <onyx/panic.h>
#include <onyx/registers.h>
#include <onyx/irq.h>
#include <onyx/platform.h>
#include <onyx/cpu.h>
#include <onyx/idt.h>
#include <onyx/apic.h>
#include <onyx/dpc.h>
#include <onyx/softirq.h>

int platform_install_irq(unsigned int irqn, struct interrupt_handler *h)
{
	UNUSED(h);
	if(irqn < NUM_IOAPIC_PINS)
		ioapic_unmask_pin(irqn);
	
	return 0;
}

void platform_send_eoi(uint64_t irq);

uintptr_t irq_handler(uint64_t irqn, registers_t *regs)
{
	/* Just return on the odd occasion that irqn > NR_IRQ */
	assert(irq_is_disabled() == true);
	/* TODO: Maybe assert'ing would be better */
	if(irqn > NR_IRQ)
		return (uintptr_t) regs;

	struct irq_context context;
	context.registers = regs;

	dispatch_irq((unsigned int) irqn, &context);

	platform_send_eoi(irqn);

	/* It's implicit that irqs are enabled since we are in a handler */
	if(!sched_is_preemption_disabled() && softirq_pending())
	{
		softirq_handle();
	}

	return (uintptr_t) context.registers;
}

int platform_allocate_msi_interrupts(unsigned int num_vectors, bool addr64,
                                     struct pci_msi_data *data)
{
	/* TODO: Balance IRQs between processors, since it's not ok to assume
	 * the current CPU, since then, IRQs become unbalanced
	 * 
	 * TODO: Magenta hardcodes some of this stuff. Is it dangerous that things
	 * are hardcoded like that?
	*/
	int vecs = x86_allocate_vectors(num_vectors);
	if(vecs < 0)
		return -1;
	/* See section 10.11.1 of the intel software developer manuals */
	uint32_t address = PCI_MSI_BASE_ADDRESS;
	address |= (apic_get_lapic_id(get_cpu_nr())) << PCI_MSI_APIC_ID_SHIFT;

	/* See section 10.11.2 of the intel software developer manuals */
	uint32_t data_val = vecs;

	data->address = address;
	data->address_high = 0;
	data->data = data_val;
	data->vector_start = vecs;
	return 0;
}

void platform_send_eoi(uint64_t irq)
{
	/* Note: MSI interrupts also require EOIs */
	lapic_send_eoi();
}

void platform_mask_irq(unsigned int irq)
{
	ioapic_mask_pin(irq);
}
