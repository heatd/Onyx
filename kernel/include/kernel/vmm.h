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
#ifndef VMM_H
#define VMM_H

#include <stdint.h>
#include <kernel/pmm.h>

typedef uint32_t DWORD;
void init_vmm();
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
//! i86 architecture defines 1024 entries per table--do not change
#define PAGES_PER_TABLE 1024
#define PAGES_PER_DIR	1024
#define MEM_REGULAR 0
#define MEM_EXEC 0x1
#define MEM_DMA 0x2
#define PAGE_DIRECTORY_INDEX(x) (((x) >> 22) & 0x3ff)
#define PAGE_TABLE_INDEX(x) (((x) >> 12) & 0x3ff)
#define PAGE_GET_PHYSICAL_ADDRESS(x) (*x & ~0xfff)

//! page table represents 4mb address space
#define PTABLE_ADDR_SPACE_SIZE 0x400000

//! directory table represents 4gb address space
#define DTABLE_ADDR_SPACE_SIZE 0x100000000

//! page sizes are 4k
#define PAGE_SIZE 4096

//! page table
typedef struct ptable {

	pt_entry entries[PAGES_PER_TABLE];
}ptable;

//! page directory

typedef struct pdirectory {

	pd_entry entries[PAGES_PER_DIR];
}pdirectory;
void init_paging();

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
inline bool pd_entry_is_present(pd_entry pd)
{
	return pd & _PDE_PRESENT;
}
inline bool pd_entry_is_user(pd_entry pd)
{
	return pd & _PDE_USER;
}
inline bool pd_entry_is_4MB(pd_entry pd)
{
	return pd & _PDE_4MB;
}
inline uintptr_t pd_entry_pfn(pd_entry pd)
{
	return pd & _PDE_FRAME;
}
inline bool pd_entry_is_writable (pd_entry pd)
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
void* kmmap(uint32_t virt, DWORD npages);

void kmunmap(void* virt, DWORD npages);

void* vmalloc(DWORD npages);

void vfree(void* ptr, DWORD npages);

#endif // VMM_H
