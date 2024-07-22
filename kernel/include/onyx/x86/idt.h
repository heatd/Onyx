/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_X86_IDT_H
#define _ONYX_X86_IDT_H

#include <stdint.h>
#include <stdlib.h>

typedef struct idt_ptr
{
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) idt_ptr_t;

typedef struct idt_entry
{
    uint16_t offset_low;
    uint16_t selector;
    uint8_t zero; /* unused, set to 0 */
    uint8_t type_attr;
    uint16_t offset_high;
    uint32_t offset_top;
    uint32_t res;
} __attribute__((packed)) idt_entry_t;

#ifdef __cplusplus
extern "C" {
#endif

void idt_create_descriptor(uint8_t entry, uint64_t offset, uint16_t selector, uint8_t flags);
void idt_set_system_gate(uint8_t entry, uint64_t offset, uint16_t selector, uint8_t flags);
void idt_load(void);
void idt_init(void);
void x86_reserve_vector(int vector, void (*handler)());
int x86_allocate_vector(void (*handler)());
int x86_allocate_vectors(int nr);
void idt_flush(uint64_t addr);

extern void isr0();
extern void isr1();
extern void isr2();
extern void isr3();
extern void isr4();
extern void isr5();
extern void isr6();
extern void isr7();
extern void isr8();
extern void isr9();
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
extern void syscall_ENTRY64_int();
extern void apic_spurious_irq();

#ifdef __cplusplus
}
#endif

#endif
