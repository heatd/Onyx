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
#ifndef _IDT_H
#define _IDT_H
#include <stdlib.h>
#include <stdint.h>
#ifdef __i386__
struct idt_ptr
{
	uint16_t limit;
	uint32_t base;
}__attribute__((packed));
#elif defined (__x86_64__)
struct idt_ptr
{
	uint16_t limit;
	uint64_t base;
}
#endif

typedef struct idt_ptr idt_ptr_t;
#ifdef __i386__
struct IDT_entry
{
	uint16_t offset_low;
	uint16_t selector;
	uint8_t zero;/* unused, set to 0 */
	uint8_t type_attr;
	uint16_t offset_high;
}__attribute__((packed));
#elif defined (__x86_64__)
struct IDT_entry
{
	uint16_t offset_low;
	uint16_t selector;
	uint8_t zero;/* unused, set to 0 */
	uint8_t type_attr;
	uint16_t offset_high;
	uint32_t offset_top;
}__attribute__((packed));
#endif

typedef struct IDT_entry idt_entry_t;
#ifdef __i386__
void idt_create_descriptor(uint8_t entry,uint32_t offset,uint16_t selector,uint8_t flags);
#elif defined(__x86_64__)
void idt_create_descriptor(uint8_t entry,uint64_t offset,uint16_t selector,uint8_t flags);
#endif
void load_idt();
void init_idt();


void isr0 ();
void isr1();
void isr2 ();
void isr3 ();
void isr4 ();
void isr5 ();
void isr6 ();
void isr7 ();
void isr8 ();
void isr9 ();
void isr10();
void isr11();
void isr12();
void isr13();
void isr14();
void isr15();
void isr16();
void isr17();
void isr18();
void isr19();
void isr20();
void isr21();
void isr22();
void isr23();
void isr24();
void isr25();
void isr26();
void isr27();
void isr28();
void isr29();
void isr30();
void isr31();
void irq0();
void irq1();
void irq2();
void irq3();
void irq4();
void irq5();
void irq6();
void irq7();
void irq8();
void irq9();
void irq10();
void irq11();
void irq12();
void irq13();
void irq14();
void irq15();
void _syscall();
void _yield();

#endif /* _IDT_H */
