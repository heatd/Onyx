/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
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
#include <onyx/x86/idt.h>
#include <onyx/x86/apic.h>
#include <onyx/x86/isr.h>
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

void check_for_resched(struct irq_context *context)
{
	struct thread *curr = get_current_thread();
	if(curr && sched_needs_resched(curr))
	{
		curr->flags &= ~THREAD_NEEDS_RESCHED;
		context->registers = (registers_t *) sched_preempt_thread(context->registers);
	}
}

unsigned long irq_handler(struct registers *regs)
{
	/* Just return on the odd occasion that irqn > NR_IRQ */
	assert(irq_is_disabled() == true);

	auto irqn = regs->int_no - EXCEPTION_VECTORS_END;

	if(irqn > NR_IRQ + EXCEPTION_VECTORS_END)
		panic("Invalid IRQ %u received\n", irqn);

	struct irq_context context;
	context.registers = regs;
	context.irq_nr = irqn;

	dispatch_irq((unsigned int) irqn, &context);

	/* It's implicit that irqs are enabled since we are in a handler */
	if(!sched_is_preemption_disabled() && softirq_pending())
	{
		softirq_handle();
	}

	check_for_resched(&context);

	return (unsigned long) context.registers;
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

	size_t irq_stub_size = 12;
	unsigned int irq_offset = vecs - 32;

	data->irq_offset = irq_offset;

	for(unsigned int i = 0; i < num_vectors; i++)
	{
		int vector = vecs + i;
		void(*irq_stub_handler)() = (void (*)())((char*) &irq0 + irq_stub_size * 
		                            (irq_offset + i));
		x86_reserve_vector(vector, irq_stub_handler);
	}

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
