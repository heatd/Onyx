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
#include <kernel/gdt.h>
#include <string.h>
static gdt_ptr_t gdt_ptr;
static gdt_entry_t entries[6];
static tss_entry_t tss_entry;
static void install_tss();
void init_gdt()
{
	memset(&entries, 0, sizeof(gdt_entry_t) * 6);
	memset(&gdt_ptr, 0, sizeof(gdt_ptr));
	memset(&tss_entry, 0, sizeof(tss_entry_t));
	create_descriptor(0, 0, 0, 0, 0);
	create_descriptor(1, 0, 0xFFFFFFFF, 0x9E, 0xCF);
	create_descriptor(2, 0, 0xFFFFFFFF, 0x92, 0xCF);
	create_descriptor(3, 0, 0xFFFFFFFF, 0xFE, 0xCF);
	create_descriptor(4, 0, 0xFFFFFFFF, 0xF2, 0xCF);
	install_tss();
	load_gdt();
}

void gdt_flush(uint32_t);
void create_descriptor(uint32_t entrynum, uint32_t base, uint32_t limit,
		       uint8_t access, uint8_t granularity)
{
	entries[entrynum].base_low = (base & 0xFFFF);
	entries[entrynum].base_middle = (base >> 16) & 0xFF;
	entries[entrynum].base_high = (base >> 24) & 0xFF;

	entries[entrynum].limit_low = (limit & 0xFFFF);
	entries[entrynum].granularity = (limit >> 16) & 0x0F;
	entries[entrynum].granularity |= granularity & 0xF0;
	entries[entrynum].access = access;

}

void tss_flush();
static void install_tss()
{
	uint32_t base = (uint32_t) &tss_entry;
	uint32_t limit = sizeof(tss_entry);

	create_descriptor(5, base, limit, 0xE9, 0);
	memset(&tss_entry, 0, sizeof(tss_entry));
	tss_entry.ss0 = 0x10;
	tss_entry.esp0 = (uint32_t) 0xC03F6000;
	tss_entry.cs = 0x0b;
	tss_entry.ss = tss_entry.ds = tss_entry.es = tss_entry.fs =
	    tss_entry.gs = 0x13;
}

void load_gdt()
{
	gdt_ptr.limit = (sizeof(gdt_entry_t) * 6) - 1;
	gdt_ptr.base = (uint32_t) & entries;
	gdt_flush((uint32_t) & gdt_ptr);
	tss_flush();
}
