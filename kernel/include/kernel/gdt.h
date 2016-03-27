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
#ifndef _GDT_H
#define _GDT_H

#include <stdint.h>
struct gdt_ptr
{
	uint16_t limit;
	uint32_t base;

}__attribute__((packed));
struct gdt_entry_struct
{
   uint16_t limit_low;           /* The lower 16 bits of the limit. */
   uint16_t base_low;            /* The lower 16 bits of the base. */
   uint8_t  base_middle;         /* The next 8 bits of the base. */
   uint8_t  access;              /* Access flags, determine what ring this segment can be used in. */
   uint8_t  granularity;
   uint8_t  base_high;           /* The last 8 bits of the base. */
} __attribute__((packed));
typedef struct gdt_entry_struct gdt_entry_t;
typedef struct gdt_ptr gdt_ptr_t;
/* A struct describing a Task State Segment. */
struct tss_entry_struct
{
   uint32_t prev_tss;   /* The previous TSS - if we used hardware task switching this would form a linked list. */
   uint32_t esp0;       /* The stack pointer to load when we change to kernel mode. */
   uint32_t ss0;        /* The stack segment to load when we change to kernel mode. */
   uint32_t esp1;       /* everything below here is unusued now.. */
   uint32_t ss1;
   uint32_t esp2;
   uint32_t ss2;
   uint32_t cr3;
   uint32_t eip;
   uint32_t eflags;
   uint32_t eax;
   uint32_t ecx;
   uint32_t edx;
   uint32_t ebx;
   uint32_t esp;
   uint32_t ebp;
   uint32_t esi;
   uint32_t edi;
   uint32_t es;
   uint32_t cs;
   uint32_t ss;
   uint32_t ds;
   uint32_t fs;
   uint32_t gs;
   uint32_t ldt;
   uint16_t trap;
   uint16_t iomap_base;
} __attribute__((packed));

typedef struct tss_entry_struct tss_entry_t;
void load_gdt();
void create_descriptor(uint32_t entrynum,uint32_t base,uint32_t limit,uint8_t access,uint8_t granularity);
void init_gdt();

#endif /* _GDT_H */
