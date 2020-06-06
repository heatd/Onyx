/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <assert.h>

#include <onyx/x86/idt.h>
#include <onyx/cpu.h>

idt_ptr_t idt_ptr;
idt_entry_t idt_entries[256];
void idt_flush(uint64_t addr);
extern void _sched_yield();

void x86_reserve_vector(int vector, void (*handler)())
{
	assert(vector < 256);
	idt_create_descriptor(vector, (uintptr_t) handler, 0x08, 0x8E);
}

int x86_allocate_vector(void (*handler)())
{
	for(int i = 0; i < 256; i++)
	{
		if(idt_entries[i].selector == 0)
		{
			x86_reserve_vector(i, handler);
			return i;
		}
	}
	return -1;
}

int x86_allocate_vectors(int nr)
{
	int int_base = -1;
	int found_vecs = 0;
	for(int i = 0; i < 256; i++)
	{
		if(idt_entries[i].selector == 0)
		{
			if(!found_vecs)
				int_base = i;
			found_vecs++;
			if(found_vecs == nr)
			{
				/* Reserve the entries */
				for(int j = 0; j < nr; j++)
				{
					/* We'll use selector to mean if it is reserved */
					idt_entries[int_base + j].selector = 1;
				}
				return int_base;
			}
		}
		else
		{
			int_base = -1;
			found_vecs = 0;
		}
	}
	return -1;
}

void idt_init(void)
{
	memset(&idt_entries, 0, sizeof(idt_entry_t) * 256);

	x86_reserve_vector(0, isr0);
	x86_reserve_vector(1, isr1);
	x86_reserve_vector(2, isr2);
	x86_reserve_vector(3, isr3);
	x86_reserve_vector(4, isr4);
	x86_reserve_vector(5, isr5);
	x86_reserve_vector(6, isr6);
	x86_reserve_vector(7, isr7);
	x86_reserve_vector(8, isr8);
	x86_reserve_vector(9, isr9);
	x86_reserve_vector(10, isr10);
	x86_reserve_vector(11, isr11);
	x86_reserve_vector(12, isr12);
	x86_reserve_vector(13, isr13);
	x86_reserve_vector(14, isr14);
	x86_reserve_vector(15, isr15);
	x86_reserve_vector(16, isr16);
	x86_reserve_vector(17, isr17);
	x86_reserve_vector(18, isr18);
	x86_reserve_vector(19, isr19);
	x86_reserve_vector(20, isr20);
	x86_reserve_vector(21, isr21);
	x86_reserve_vector(22, isr22);
	x86_reserve_vector(23, isr23);
	x86_reserve_vector(24, isr24);
	x86_reserve_vector(25, isr25);
	x86_reserve_vector(26, isr26);
	x86_reserve_vector(27, isr27);
	x86_reserve_vector(28, isr28);
	x86_reserve_vector(29, isr29);
	x86_reserve_vector(30, isr30);
	x86_reserve_vector(31, isr31);
	idt_set_system_gate(129,  (uint64_t) _sched_yield, 0x08, 0x8e);
	x86_reserve_vector(X86_MESSAGE_VECTOR, __cpu_handle_message);
	x86_reserve_vector(255,  apic_spurious_irq);
	idt_load();
}

void idt_create_descriptor(uint8_t entry, uint64_t offset,
			   uint16_t selector, uint8_t flags)
{
	idt_entries[entry].offset_low = offset & 0xFFFF;
	idt_entries[entry].offset_high = (offset >> 16) & 0xFFFF;
	idt_entries[entry].offset_top = (offset >> 32);
	idt_entries[entry].selector = selector;

	idt_entries[entry].zero = 0;
	idt_entries[entry].type_attr = flags;
}

void idt_set_system_gate(uint8_t entry, uint64_t offset,
	uint16_t selector, uint8_t flags)
{
	idt_entries[entry].offset_low = offset & 0xFFFF;
	idt_entries[entry].offset_high = (offset >> 16) & 0xFFFF;
	idt_entries[entry].offset_top = (offset >> 32);
	idt_entries[entry].selector = selector;

	idt_entries[entry].zero = 0;
	idt_entries[entry].type_attr = flags | 0x60;
}

void idt_load()
{
	idt_ptr.limit = sizeof(idt_entry_t) * 256 - 1;
	idt_ptr.base =  (uintptr_t) &idt_entries;
	idt_flush((uintptr_t) &idt_ptr);
}
