/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/**************************************************************************
 *
 *
 * File: irq.c
 *
 * Description: Contains irq installation functions
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <kernel/scheduler.h>
#include <kernel/task_switching.h>
#include <kernel/panic.h>
#include <kernel/registers.h>
#include <kernel/irq.h>
#include <kernel/platform.h>
#include <kernel/cpu.h>
#include <kernel/idt.h>
#include <kernel/apic.h>
#include <kernel/dpc.h>

volatile _Bool is_in_irq = false;
#define NR_IRQ 221
#define NUM_IOAPIC_PINS	24
irq_list_t *irq_routines[NR_IRQ]  =
{
	NULL
};
unsigned long irq_refs[NR_IRQ] = {0};
unsigned long rogue_irqs = 0;
_Bool isirq()
{
	return is_in_irq;
}

void irq_install_handler(int irq, irq_t handler)
{
	assert(irq < NR_IRQ);
	if(irq < NUM_IOAPIC_PINS)
		ioapic_unmask_pin((uint32_t) irq);
	irq_list_t *lst = irq_routines[irq];
	if(!lst)
	{
		lst = (irq_list_t*) malloc(sizeof(irq_list_t));
		if(!lst)
		{
			errno = ENOMEM;
			return; /* TODO: Return a value indicating an error */
		}
		memset(lst, 0, sizeof(irq_list_t));
		lst->handler = handler;
		irq_routines[irq] = lst;
		return;
	}
	while(lst->next != NULL)
		lst = lst->next;
	lst->next = (irq_list_t*) malloc(sizeof(irq_list_t));
	if(!lst->next)
	{
		errno = ENOMEM;
		return; /* See the above TODO */
	}
	lst->next->handler = handler;
	lst->next->next = NULL;
}

void irq_uninstall_handler(int irq, irq_t handler)
{
	irq_list_t *list = irq_routines[irq];
	if(list->handler == handler)
	{
		free(list);
		irq_routines[irq] = NULL;
		return;
	}
	irq_list_t *prev = NULL;
	while(list->handler != handler)
	{
		prev = list;
		list = list->next;
	}
	prev->next = list->next;
	free(list);
}

uintptr_t irq_handler(uint64_t irqn, registers_t *regs)
{
	if(irqn > NR_IRQ)
	{
		return (uintptr_t) regs;
	}
	irq_refs[irqn]++;
	uintptr_t ret = (uintptr_t) regs;
	irq_list_t *handlers = irq_routines[irqn];
	if(!handlers)
	{
		printf("irq: Unhandled interrupt at IRQ %u\n", irqn);
		rogue_irqs++;
	}
	is_in_irq = true;
	for(irq_list_t *i = handlers; i != NULL;i = i->next)
	{
		irq_t handler = i->handler;
		uintptr_t p = handler(regs);
		if(p != 0)
		{
			ret = p;
		}
	}
	is_in_irq = false;
	return ret;
}

void irq_init(void)
{
	dpc_init();
}

#define PCI_MSI_BASE_ADDRESS 0xFEE00000
#define PCI_MSI_APIC_ID_SHIFT	12
#define PCI_MSI_REDIRECTION_HINT	(1 << 3)
int platform_allocate_msi_interrupts(unsigned int num_vectors, bool addr64,
                                     struct pci_msi_data *data)
{
	/* TODO: Balance IRQs between processors, since it's not ok to assume
	 * the current CPU, since then, IRQs become unbalanced
	*/
	/* 
	 * TODO: Magenta hardcodes some of this stuff. Is it dangerous that things
	 * are hardcoded like that?
	*/
	struct processor *proc = get_processor_data();
	assert(proc != NULL);
	int vecs = x86_allocate_vectors(num_vectors);
	if(vecs < 0)
		return -1;
	/* See section 10.11.1 of the intel software developer manuals */
	uint32_t address = PCI_MSI_BASE_ADDRESS;
	address |= ((uint32_t) proc->lapic_id) << PCI_MSI_APIC_ID_SHIFT;
	
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
