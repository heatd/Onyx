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
#ifndef _VMM_H
#define _VMM_H
#include <stdint.h>
#include <kernel/pmm.h>
#include <stdbool.h>
typedef uint32_t DWORD;

void vmm_init(uint32_t framebuffer_addr);
/* Page table defines just to help the code not have "magic values"*/
#define _PTE_PRESENT		1
#define _PTE_WRITABLE		2
#define _PTE_USER			4
#define _PTE_WRITE_THROUGH	8
#define _PTE_NOT_CACHEABLE  0x10
#define _PTE_ACCESSED		0x20
#define _PTE_DIRTY			0x40
#define _PTE_PAT			0x80
#define _PTE_LV4_GLOBAL		0x200
#define _PTE_FRAME			0x7FFFF000
/*Page Directory defines to help the code not have "magic values"*/
#define _PDE_PRESENT		1
#define _PDE_WRITABLE		2
#define _PDE_USER			4
#define _PDE_PWT			8
#define _PDE_PCD			0x10
#define _PDE_ACCESSED		0x20
#define _PDE_DIRTY			0x40
#define _PDE_4MB			0x80
#define _PDE_CPU_GLOBAL		0x100
#define _PDE_LV4_GLOBAL		0x200
#define _PDE_FRAME			0x7FFFF000
typedef uint32_t pd_entry;
typedef uint32_t pt_entry;
// i686 architecture defines 1024 entries per table
#define PAGES_PER_TABLE 1024
#define PAGES_PER_DIR	1024
#define PAGE_DIRECTORY_INDEX(x) (((x) >> 22) & 0x3ff)
#define PAGE_TABLE_INDEX(x) (((x) >> 12) & 0x3ff)

// page table represents 4mb address space
#define PTABLE_ADDR_SPACE_SIZE 0x400000

// directory table represents 4gb address space
#define DTABLE_ADDR_SPACE_SIZE 0xFFFFFFFF

// page sizes are 4k
#define PAGE_SIZE 4096

// page table
typedef struct ptable {

	pt_entry entries[PAGES_PER_TABLE];
}ptable;

//! page directory

typedef struct pdirectory {

	pd_entry entries[PAGES_PER_DIR];
}pdirectory;
pdirectory* vmm_fork();
void* vmm_map(uint32_t virt, uint32_t npages,uint32_t flags);
int vmm_mark_addr_as_used(void*,size_t);
void  vmm_finish();
void* vmm_alloc_addr(size_t, _Bool);
void  vmm_free_addr(void*  address);
#define PAGE_RAM 0x1
#define PAGE_KERNEL 0x2
#define PAGE_USER 0x4
int vmm_alloc_cow(uintptr_t);
void* get_phys_addr (pdirectory* dir, uint32_t virt);
#define PAGE_READ 0x1
#define PAGE_WRITE 0x2
#define PAGE_EXECUTABLE 0x4
#define PAGE_RW PAGE_READ | PAGE_WRITE
#define PAGE_RWE PAGE_RW | PAGE_EXECUTABLE
#define kernel_lowest_addr 0xC0000000
#define user_lowest_addr  0x400000
typedef struct area_strct
{
	uintptr_t addr; // Address of pages

	size_t size; // Size in pages

	uint8_t type; // Type of page ( its type is uint8_t just to save some memory)

	uint8_t protection; // R/W, just read, executable, etc...

	_Bool is_used;
	struct area_strct* next; // The next area_struct in the linked list
}area_struct;
inline void pt_entry_set_bit(pt_entry* pt,uint32_t bit)
{
	*pt|= bit;
}
inline void pt_entry_unset_bit(pt_entry* pt,uint32_t bit)
{
	*pt&=~bit;
}
inline void pt_entry_set_frame(pt_entry* pt, uintptr_t p_addr)
{
	*pt=(*pt & ~_PTE_FRAME) | p_addr;
}
inline int pt_entry_is_present(pt_entry pt)
{
	return pt & _PTE_PRESENT;
}
inline int pt_entry_is_writable (pt_entry pt)
{
	return pt & _PTE_WRITABLE;
}

inline uintptr_t pt_entry_pfn (pt_entry pt)
{
	return pt & _PTE_FRAME;
}
inline void pd_entry_set_bit(pd_entry* pd,uint32_t bit)
{
	*pd|= bit;
}
inline void pd_entry_unset_bit(pd_entry* pd, uint32_t bit)
{
	*pd&=~bit;
}
inline void pd_entry_set_frame(pd_entry* pd,uintptr_t paddr)
{
	*pd=(*pd & ~_PDE_FRAME) | paddr;
}
inline _Bool pd_entry_is_present(pd_entry pd)
{
	return pd & _PDE_PRESENT;
}
inline _Bool pd_entry_is_user(pd_entry pd)
{
	return pd & _PDE_USER;
}
inline _Bool pd_entry_is_4MB(pd_entry pd)
{
	return pd & _PDE_4MB;
}
inline uintptr_t pd_entry_pfn(pd_entry pd)
{
	return pd & _PDE_FRAME;
}
inline _Bool pd_entry_is_writable (pd_entry pd)
{
	return pd & _PDE_WRITABLE;
}
inline void pd_entry_enable_global(pd_entry pd)
{
	pd|=_PDE_CPU_GLOBAL;
}
inline void _flush_tlb_page(unsigned long addr)
{
   	asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}
void* kmmap(uint32_t virt, uint32_t npages,uint32_t flags);

void kmunmap(void* virt, uint32_t npages);

void* valloc(uint32_t npages);

void vfree(void* ptr, uint32_t npages);

int switch_directory (pdirectory* dir);
#endif
