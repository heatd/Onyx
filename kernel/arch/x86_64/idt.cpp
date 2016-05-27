/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <string.h>
#include <kernel/idt.h>
idt_ptr_t idt_ptr;
idt_entry_t idt_entries[256];
extern "C" void IDT_Flush(uint64_t);
namespace IDT
{
void Init()
{
	memset(&idt_entries, 0, sizeof(idt_entry_t) * 256);

	CreateDescriptor(0, (uint64_t) isr0, 0x08, 0x8E);
	CreateDescriptor(1, (uint64_t) isr1, 0x08, 0x8E);
	CreateDescriptor(2, (uint64_t) isr2, 0x08, 0x8E);
	CreateDescriptor(3, (uint64_t) isr3, 0x08, 0x8E);
	CreateDescriptor(4, (uint64_t) isr4, 0x08, 0x8E);
	CreateDescriptor(5, (uint64_t) isr5, 0x08, 0x8E);
	CreateDescriptor(6, (uint64_t) isr6, 0x08, 0x8E);
	CreateDescriptor(7, (uint64_t) isr7, 0x08, 0x8E);
	CreateDescriptor(8, (uint64_t) isr8, 0x08, 0x8E);
	CreateDescriptor(9, (uint64_t) isr9, 0x08, 0x8E);
	CreateDescriptor(10, (uint64_t) isr10, 0x08, 0x8E);
	CreateDescriptor(11, (uint64_t) isr11, 0x08, 0x8E);
	CreateDescriptor(12, (uint64_t) isr12, 0x08, 0x8E);
	CreateDescriptor(13, (uint64_t) isr13, 0x08, 0x8E);
	CreateDescriptor(14, (uint64_t) isr14, 0x08, 0x8E);
	CreateDescriptor(15, (uint64_t) isr15, 0x08, 0x8E);
	CreateDescriptor(16, (uint64_t) isr16, 0x08, 0x8E);
	CreateDescriptor(17, (uint64_t) isr17, 0x08, 0x8E);
	CreateDescriptor(18, (uint64_t) isr18, 0x08, 0x8E);
	CreateDescriptor(19, (uint64_t) isr19, 0x08, 0x8E);
	CreateDescriptor(20, (uint64_t) isr20, 0x08, 0x8E);
	CreateDescriptor(21, (uint64_t) isr21, 0x08, 0x8E);
	CreateDescriptor(22, (uint64_t) isr22, 0x08, 0x8E);
	CreateDescriptor(23, (uint64_t) isr23, 0x08, 0x8E);
	CreateDescriptor(24, (uint64_t) isr24, 0x08, 0x8E);
	CreateDescriptor(25, (uint64_t) isr25, 0x08, 0x8E);
	CreateDescriptor(26, (uint64_t) isr26, 0x08, 0x8E);
	CreateDescriptor(27, (uint64_t) isr27, 0x08, 0x8E);
	CreateDescriptor(28, (uint64_t) isr28, 0x08, 0x8E);
	CreateDescriptor(29, (uint64_t) isr29, 0x08, 0x8E);
	CreateDescriptor(30, (uint64_t) isr30, 0x08, 0x8E);
	CreateDescriptor(31, (uint64_t) isr31, 0x08, 0x8E);
	/* IRQ descriptors */
	CreateDescriptor(32, (uint64_t) irq0, 0x08, 0x8E);
	CreateDescriptor(33, (uint64_t) irq1, 0x08, 0x8E);
	CreateDescriptor(34, (uint64_t) irq2, 0x08, 0x8E);
	CreateDescriptor(35, (uint64_t) irq3, 0x08, 0x8E);
	CreateDescriptor(36, (uint64_t) irq4, 0x08, 0x8E);
	CreateDescriptor(37, (uint64_t) irq5, 0x08, 0x8E);
	CreateDescriptor(38, (uint64_t) irq6, 0x08, 0x8E);
	CreateDescriptor(39, (uint64_t) irq7, 0x08, 0x8E);
	CreateDescriptor(40, (uint64_t) irq8, 0x08, 0x8E);
	CreateDescriptor(41, (uint64_t) irq9, 0x08, 0x8E);
	CreateDescriptor(42, (uint64_t) irq10, 0x08, 0x8E);
	CreateDescriptor(43, (uint64_t) irq11, 0x08, 0x8E);
	CreateDescriptor(44, (uint64_t) irq12, 0x08, 0x8E);
	CreateDescriptor(45, (uint64_t) irq13, 0x08, 0x8E);
	CreateDescriptor(46, (uint64_t) irq14, 0x08, 0x8E);
	CreateDescriptor(47, (uint64_t) irq15, 0x08, 0x8E);
	Load();
}

void CreateDescriptor(uint8_t entry, uint64_t offset,
			   uint16_t selector, uint8_t flags)
{
	idt_entries[entry].offset_low = offset & 0xFFFF;
	idt_entries[entry].offset_high = (offset >> 16) & 0xFFFF;
	idt_entries[entry].offset_top = (offset >> 32);
	idt_entries[entry].selector = selector;

	idt_entries[entry].zero = 0;
	idt_entries[entry].type_attr = flags | 0x60;

}

void Load()
{
	idt_ptr.limit = sizeof(idt_entry_t) * 256 - 1;
	idt_ptr.base = (uint64_t) & idt_entries;
	IDT_Flush((uint64_t) & idt_ptr);
}

}
