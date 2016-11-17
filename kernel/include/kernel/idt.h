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
#ifndef _IDT_H
#define _IDT_H
#include <stdlib.h>
#include <stdint.h>

#if defined (__x86_64__)
struct idt_ptr
{
	uint16_t limit;
	uint64_t base;
}__attribute__((packed));
#endif

typedef struct idt_ptr idt_ptr_t;
#if defined (__x86_64__)
struct IDT_entry
{
	uint16_t offset_low;
	uint16_t selector;
	uint8_t zero;/* unused, set to 0 */
	uint8_t type_attr;
	uint16_t offset_high;
	uint32_t offset_top;
	uint32_t res;
}__attribute__((packed));
#endif
typedef struct IDT_entry idt_entry_t;

void idt_create_descriptor(uint8_t entry,uint64_t offset,uint16_t selector,uint8_t flags);
void idt_load();
void idt_init();
extern void isr0 ();
extern void isr1();
extern void isr2 ();
extern void isr3 ();
extern void isr4 ();
extern void isr5 ();
extern void isr6 ();
extern void isr7 ();
extern void isr8 ();
extern void isr9 ();
extern void isr10();
extern void isr11();
extern void isr12();
extern void isr13();
extern void isr14();
extern void isr15();
extern void isr16();
extern void isr17();
extern void isr18();
extern void isr19();
extern void isr20();
extern void isr21();
extern void isr22();
extern void isr23();
extern void isr24();
extern void isr25();
extern void isr26();
extern void isr27();
extern void isr28();
extern void isr29();
extern void isr30();
extern void isr31();
extern void irq0();
extern void irq1();
extern void irq2();
extern void irq3();
extern void irq4();
extern void irq5();
extern void irq6();
extern void irq7();
extern void irq8();
extern void irq9();
extern void irq10();
extern void irq11();
extern void irq12();
extern void irq13();
extern void irq14();
extern void irq15();
extern void irq16();
extern void irq17();
extern void irq18();
extern void irq19();
extern void irq20();
extern void irq21();
extern void irq22();
extern void irq23();
extern void __syscall_int();
#endif /* _IDT_H */
