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
#include <string.h>
#include <kernel/idt.h>
idt_ptr_t idt_ptr;
idt_entry_t idt_entries[256];
extern "C" void IDT_Flush(uint32_t);
void init_idt()
{
	memset(&idt_entries, 0, sizeof(idt_entry_t) * 256);

	idt_create_descriptor( 0, (uint32_t)isr0 , 0x08, 0x8E);
	idt_create_descriptor( 1, (uint32_t)isr1 , 0x08, 0x8E);
	idt_create_descriptor( 2, (uint32_t)isr2 , 0x08, 0x8E);
	idt_create_descriptor( 3, (uint32_t)isr3 , 0x08, 0x8E);
	idt_create_descriptor( 4, (uint32_t)isr4 , 0x08, 0x8E);
	idt_create_descriptor( 5, (uint32_t)isr5 , 0x08, 0x8E);
	idt_create_descriptor( 6, (uint32_t)isr6 , 0x08, 0x8E);
	idt_create_descriptor( 7, (uint32_t)isr7 , 0x08, 0x8E);
	idt_create_descriptor( 8, (uint32_t)isr8 , 0x08, 0x8E);
	idt_create_descriptor( 9, (uint32_t)isr9 , 0x08, 0x8E);
	idt_create_descriptor(10, (uint32_t)isr10, 0x08, 0x8E);
	idt_create_descriptor(11, (uint32_t)isr11, 0x08, 0x8E);
	idt_create_descriptor(12, (uint32_t)isr12, 0x08, 0x8E);
	idt_create_descriptor(13, (uint32_t)isr13, 0x08, 0x8E);
	idt_create_descriptor(14, (uint32_t)isr14, 0x08, 0x8E);
	idt_create_descriptor(15, (uint32_t)isr15, 0x08, 0x8E);
	idt_create_descriptor(16, (uint32_t)isr16, 0x08, 0x8E);
	idt_create_descriptor(17, (uint32_t)isr17, 0x08, 0x8E);
	idt_create_descriptor(18, (uint32_t)isr18, 0x08, 0x8E);
	idt_create_descriptor(19, (uint32_t)isr19, 0x08, 0x8E);
	idt_create_descriptor(20, (uint32_t)isr20, 0x08, 0x8E);
	idt_create_descriptor(21, (uint32_t)isr21, 0x08, 0x8E);
	idt_create_descriptor(22, (uint32_t)isr22, 0x08, 0x8E);
	idt_create_descriptor(23, (uint32_t)isr23, 0x08, 0x8E);
	idt_create_descriptor(24, (uint32_t)isr24, 0x08, 0x8E);
	idt_create_descriptor(25, (uint32_t)isr25, 0x08, 0x8E);
	idt_create_descriptor(26, (uint32_t)isr26, 0x08, 0x8E);
	idt_create_descriptor(27, (uint32_t)isr27, 0x08, 0x8E);
	idt_create_descriptor(28, (uint32_t)isr28, 0x08, 0x8E);
	idt_create_descriptor(29, (uint32_t)isr29, 0x08, 0x8E);
	idt_create_descriptor(30, (uint32_t)isr30, 0x08, 0x8E);
	idt_create_descriptor(31, (uint32_t)isr31, 0x08, 0x8E);
	idt_create_descriptor(32, (uint32_t)irq0, 0x08, 0x8E);
	idt_create_descriptor(33, (uint32_t)irq1, 0x08, 0x8E);
	idt_create_descriptor(34, (uint32_t)irq2, 0x08, 0x8E);
	idt_create_descriptor(35, (uint32_t)irq3, 0x08, 0x8E);
	idt_create_descriptor(36, (uint32_t)irq4, 0x08, 0x8E);
	idt_create_descriptor(37, (uint32_t)irq5, 0x08, 0x8E);
	idt_create_descriptor(38, (uint32_t)irq6, 0x08, 0x8E);
	idt_create_descriptor(39, (uint32_t)irq7, 0x08, 0x8E);
	idt_create_descriptor(40, (uint32_t)irq8, 0x08, 0x8E);
	idt_create_descriptor(41, (uint32_t)irq9, 0x08, 0x8E);
	idt_create_descriptor(42, (uint32_t)irq10, 0x08, 0x8E);
	idt_create_descriptor(43, (uint32_t)irq11, 0x08, 0x8E);
	idt_create_descriptor(44, (uint32_t)irq12, 0x08, 0x8E);
	idt_create_descriptor(45, (uint32_t)irq13, 0x08, 0x8E);
	idt_create_descriptor(46, (uint32_t)irq14, 0x08, 0x8E);
	idt_create_descriptor(47, (uint32_t)irq15, 0x08, 0x8E);

	idt_create_descriptor(0x80, (uint32_t)_syscall,0x08,0x8E);//System call interrupt

	load_idt();
}
void idt_create_descriptor(uint8_t entry,uint32_t offset,uint16_t selector,uint8_t flags)
{
	idt_entries[entry].offset_low  = offset & 0xFFFF;
	idt_entries[entry].offset_high = (offset >> 16) & 0xFFFF;

	idt_entries[entry].selector = selector;

	idt_entries[entry].zero = 0;
	idt_entries[entry].type_attr = flags | 0x60;

}
void load_idt()
{
	idt_ptr.limit = sizeof(idt_entry_t) * 256 - 1;
	idt_ptr.base  = (uint32_t)&idt_entries;
	IDT_Flush((uint32_t)&idt_ptr);
}
