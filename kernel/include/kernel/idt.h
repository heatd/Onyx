/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef IDT_H
#define IDT_H

#include <stdlib.h>
#include <stdint.h>
struct idt_ptr
{
	uint16_t limit;
	uint32_t base;
}__attribute__((packed));

typedef struct idt_ptr idt_ptr_t;

struct IDT_entry
{
	uint16_t offset_low;
	uint16_t selector;
	uint8_t zero;// unused, set to 0
	uint8_t type_attr;
	uint16_t offset_high;
}__attribute__((packed));

typedef struct IDT_entry idt_entry_t;

void idt_create_descriptor(uint8_t entry,uint32_t offset,uint16_t selector,uint8_t flags);
void load_idt();
void idt_init();
idt_ptr_t idt_ptr;
idt_entry_t idt_entries[256];


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
extern void _syscall();
#endif // IDT_H
