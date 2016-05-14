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
/**************************************************************************
 *
 *
 * File: vmm.c
 *
 * Description: Implementation of virtual memory on x86
 *
 * Date: 4/2/2016
 *
 *
 **************************************************************************/
#include <kernel/vmm.h>
#include <kernel/spinlock.h>
#include <stddef.h>
#include <string.h>
#include <kernel/mm.h>
#include <kernel/pmm.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <kernel/panic.h>
#include <kernel/bitfield.h>
#include <kernel/compiler.h>
#include <stdbool.h>
/*! virtual address */
typedef uint32_t virtual_addr;
static area_struct *first = NULL;
void loadPageDirectory(pdirectory *);

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
   	__asm__ __volatile__ ("invlpg (%0)" ::"r" (addr) : "memory");
}
static int alloc_page(pt_entry * pt)
{
	void *p = pmalloc(1);
	if (!p)
		return 1;
	pt_entry_set_frame(pt, (uintptr_t) p);
	pt_entry_set_bit(pt, _PTE_PRESENT);

	return 0;
}

static void free_page(pt_entry * pt)
{
	void *p = (void *) pt_entry_pfn(*pt);
	if (p)
		pfree(1, p);

	pt_entry_unset_bit(pt, _PTE_PRESENT);
}

inline pt_entry *ptable_lookup_entry(ptable * p, virtual_addr addr)
{

	if (p)
		return &p->entries[PAGE_TABLE_INDEX(addr)];
	return 0;
}

inline pd_entry *pdirectory_lookup_entry(pdirectory * p, virtual_addr addr)
{

	if (p)
		return &p->entries[PAGE_TABLE_INDEX(addr)];
	return 0;
}

pdirectory *_cur_directory = 0;

int _switch_directory(pdirectory *dir)
{
	if (!dir)
		return 1;
	_cur_directory = dir;
	loadPageDirectory(dir);
	return 0;
}

pdirectory *get_directory()
{

	return (pdirectory *) 0xFFFFF000;
}

void vmm_init(uint32_t framebuffer_addr)
{
	ptable *mb = (ptable *) 0xC03F0000;
	memset(mb, 0, sizeof(ptable));
	ptable *table = (ptable *) 0xC03F1000;
	memset(table, 0, sizeof(ptable));
	ptable *framebuffer = (ptable *) 0xC03F3000;
	memset(table, 0, sizeof(ptable));
	for (int i = 0, frame = 0, virt = 0; i < 1024;
	     i++, frame += 4096, virt += 4096) {
		if(i == 0) /* Unmap the NULL page (0x0) */
			continue;
		pt_entry page = 0;
		pt_entry_set_bit(&page, _PTE_PRESENT);
		pt_entry_set_frame(&page, frame);
		pt_entry_set_bit(&page, _PTE_USER);
		pt_entry_set_bit(&page, _PTE_WRITABLE);
		mb->entries[PAGE_TABLE_INDEX(virt)] = page;
	}
	for (int i = 0, frame = framebuffer_addr, virt = framebuffer_addr;
	     i < 1024; i++, frame += 4096, virt += 4096) {
		pt_entry page = 0;
		pt_entry_set_bit(&page, _PTE_PRESENT);
		pt_entry_set_bit(&page, _PTE_USER);
		pt_entry_set_bit(&page, _PTE_WRITABLE);
		pt_entry_set_frame(&page, frame);
		framebuffer->entries[PAGE_TABLE_INDEX(virt)] = page;
	}
	for (int i = 0, frame = 0x000000, virt = 0xC0000000; i < 1024;
	     i++, frame += 4096, virt += 4096) {
		pt_entry page = 0;
		pt_entry_set_bit(&page, _PTE_PRESENT);
		pt_entry_set_bit(&page, _PTE_USER);
		pt_entry_set_bit(&page, _PTE_WRITABLE);
		pt_entry_set_frame(&page, frame);

		table->entries[PAGE_TABLE_INDEX(virt)] = page;
	}
	pdirectory *dir = (pdirectory *) 0xC03F2000;
	memset(dir, 0, sizeof(pdirectory));
	pd_entry *entry = &dir->entries[PAGE_DIRECTORY_INDEX(0xC0000000)];
	pd_entry_set_bit(entry, _PDE_PRESENT);
	pd_entry_set_bit(entry, _PDE_WRITABLE);
	pd_entry_set_bit(entry, _PDE_USER);
	table = (ptable *) 0x3F1000;
	pd_entry_set_frame(entry, (uintptr_t) table);
	pd_entry *entry2 = &dir->entries[PAGE_DIRECTORY_INDEX(0)];
	pd_entry_set_bit(entry2, _PDE_PRESENT);
	pd_entry_set_bit(entry2, _PDE_WRITABLE);
	pd_entry_set_bit(entry2, _PDE_USER);
	mb = (ptable *) 0x3F0000;
	pd_entry_set_frame(entry2, (uintptr_t) mb);
	pd_entry *entry3 = &dir->entries[PAGE_DIRECTORY_INDEX(0xFFC00000)];
	pd_entry_set_bit(entry3, _PDE_PRESENT);
	pd_entry_set_bit(entry3, _PDE_WRITABLE);
	pd_entry *framebuf =
	    &dir->entries[PAGE_DIRECTORY_INDEX(framebuffer_addr)];
	pd_entry_set_bit(framebuf, _PDE_PRESENT);
	pd_entry_set_bit(framebuf, _PDE_WRITABLE);
	pd_entry_set_bit(framebuf, _PDE_USER);
	framebuffer = (ptable *) 0x3F3000;
	pd_entry_set_frame(framebuf, (uintptr_t) framebuffer);
	dir = (pdirectory *) 0x3F2000;
	pd_entry_set_frame(entry3, (uintptr_t) dir);
	switch_directory(dir);
}

/* Finish installing the VMM */
void vmm_finish()
{
	first = kmalloc(sizeof(area_struct));
	first->addr = 0x0;
	first->size = 1024;
	first->is_used = true;
	first->type = PAGE_RAM | PAGE_KERNEL;
	first->protection = PAGE_RW;
	area_struct *area = kmalloc(sizeof(area_struct));
	first->next = area;
	area->addr = 0xC0000000;
	area->size = 3840;
	area->type = PAGE_RAM | PAGE_KERNEL;
	area->protection = PAGE_RWE;
	area->is_used = true;
	area->next = NULL;

}
void *vmm_map(uint32_t virt, uint32_t npages, uint32_t ptflags,uint32_t pdflags)
{
	if (!npages)
		return NULL;
	pdirectory *pdir = (pdirectory *)0xFFFFF000;
	pd_entry *entry = &pdir->entries[PAGE_DIRECTORY_INDEX(virt)];
	ptable *pt = NULL;
	if (pd_entry_is_4MB(*entry) == 1 && pd_entry_pfn(*entry) != 0)
		return NULL;
	if (npages == 1024) {
		pd_entry_set_bit(entry, _PDE_PRESENT);
		if(ptflags != 0 && pdflags != 0){
			if(pdflags == _PDE_WRITABLE) {
				pd_entry_set_bit(entry,_PDE_WRITABLE);
			}else if(pdflags == (_PDE_WRITABLE | _PDE_USER)) {
				pd_entry_set_bit(entry,_PDE_USER);
				pd_entry_set_bit(entry,_PDE_WRITABLE);
			}
		}
		pd_entry_set_bit(entry, _PDE_4MB);
		void *ptr = pmalloc(1024);
		pd_entry_set_frame(entry, (uintptr_t) ptr);
		return (void *)virt;
	}
	if (pd_entry_is_present(*entry))
		pt = (ptable *) (0xFFC00000 + (virt / 0x400000 * 0x1000));
	else {
		pt = (ptable *) pmalloc(1);
		if (!pt)
			panic("No free blocks");
		pd_entry_set_bit(entry, _PDE_PRESENT);
		if(ptflags != 0 && pdflags != 0){
			if(pdflags == _PDE_WRITABLE) {
				pd_entry_set_bit(entry,_PDE_WRITABLE);
			}else if(pdflags == (_PDE_WRITABLE | _PDE_USER)) {
				pd_entry_set_bit(entry,_PDE_USER);
				pd_entry_set_bit(entry,_PDE_WRITABLE);
			}
		}
		pd_entry_set_frame(entry, (uintptr_t) pt);
		pt = (ptable *) (0xFFC00000 + (virt / 0x400000 * 0x1000));
		memset(pt,0,sizeof(ptable));
	}
	uint32_t ret_addr = 0;
	for (unsigned int i = 0, vaddr = virt; i < npages; i++, vaddr += 4096) {
		if (i == 0)
			ret_addr = vaddr;
		/* create a new page */
		pt_entry page = 0;
		if (alloc_page(&page) == 1) {
			printf("Failed to map page 0x%X\n", vaddr);
			panic("No more physical memory");
		}
		if(ptflags != 0 && pdflags != 0){
			if(ptflags == _PTE_WRITABLE) {
				pt_entry_set_bit(&page,_PTE_WRITABLE);
			}else if(ptflags == (_PTE_WRITABLE | _PTE_USER)) {
				pt_entry_set_bit(&page,_PTE_USER);
				pt_entry_set_bit(&page,_PTE_WRITABLE);
			}
		}
		/*...and add it to the page table */
		pt->entries[PAGE_TABLE_INDEX(vaddr)] = page;
	}
	return (void *) ret_addr;
}
void *_kmmap(uint32_t virt, uint32_t npages, uint32_t flags)
{
	uint32_t ptflags = 0, pdflags = 0;
	if(flags == MAP_WRITE) {
		ptflags = _PTE_WRITABLE;
		pdflags = _PDE_WRITABLE;
	}else if(flags == (MAP_WRITE | MAP_USER)) {
		ptflags = _PTE_WRITABLE | _PTE_USER;
		pdflags = _PDE_WRITABLE | _PDE_USER;
	}
	uint32_t vaddr = virt;
	if (npages > 1024) {
		uint32_t number_of_allocs = npages / 1024;
		for (unsigned int i = 0; i < number_of_allocs; i++) {
			vmm_map(vaddr, 1024, ptflags, pdflags);
			vaddr += 0x400000;
		}
		vmm_map(vaddr, npages % 1024, ptflags, pdflags);
	} else
		vmm_map(vaddr, npages, ptflags, pdflags);
	return (void *) vaddr;
}
void _kmunmap(void *virt, size_t npages)
{
	if (!virt)
		return;
	if (!npages)
		return;
	pdirectory *pdir = get_directory();
	if (!pdir)
		return;
	pd_entry *entry =
	    &pdir->entries[PAGE_DIRECTORY_INDEX((uint32_t) virt)];
	if (!pd_entry_is_present(*entry))
		return;
	ptable *pt = (ptable *) ((uint32_t) (0xFFC00000 + (uint32_t)virt / 0x400000 * 0x1000));
	if (!pt_entry_is_present
	    (pt->entries[PAGE_TABLE_INDEX((uint32_t) virt)]))
		return;
	for (uint32_t i = 0, vaddr = (uint32_t) virt; i < npages;
	     i++, vaddr += 4096) {

		pt_entry *page = &pt->entries[PAGE_TABLE_INDEX(vaddr)];
		free_page(page);
		_flush_tlb_page(vaddr);
	}
	for (uint32_t i = 0; i < 1024; i++)	/*Optimization */
	{
		if (pt_entry_is_present(pt->entries[i]))
			break;
		else if (i == 1023)
			kmunmap((void *) pt, 1);
	}
}
void *vmm_alloc_addr(size_t num_pages, _Bool is_kernel)
{
	if (unlikely(is_kernel == true)) {
		area_struct *tosearch = first;
		area_struct *last_kernel = first;
		/* Search the linked list */
		while (1) {
			if (tosearch->addr >= kernel_lowest_addr) {
				last_kernel = tosearch;
				if (last_kernel->size >= num_pages
				    && last_kernel->is_used == false) {
					last_kernel->is_used = true;
					return (void *) last_kernel->addr;
				}
			}
			if (tosearch->next == NULL)
				break;
			tosearch = tosearch->next;
		}
		area_struct *new_area = kmalloc(sizeof(area_struct));
		memset(new_area, 0, sizeof(area_struct));
		tosearch->next = new_area;
		new_area->addr =
		    last_kernel->addr + last_kernel->size * PAGE_SIZE;
		if (new_area->addr + num_pages * PAGE_SIZE >= 0xFFC00000) {
			/* Out of virtual memory, return */
			/* This if statement is critical, so its impossible for attackers to exploit the vmm to map over the recursive mapping */
			return NULL;
		}
		new_area->size = num_pages;
		new_area->type = PAGE_RAM | PAGE_KERNEL;
		new_area->protection = PAGE_RW;
		new_area->is_used = true;
		return (void *) new_area->addr;
	} else			/* If is_kernel != true, then the pages are going to be user accessible */
	{
		area_struct *tosearch = first;
		area_struct *last_user = first;
		/* Search the linked list */
		while (1) {
			if (tosearch->addr < kernel_lowest_addr) {
				last_user = tosearch;
				if (last_user->size >= num_pages
				    && last_user->is_used == false) {
					last_user->is_used = true;
					return (void *) last_user->addr;
				}
			}
			if (tosearch->next == NULL)
				break;
			tosearch = tosearch->next;
		}
		area_struct *new_area = kmalloc(sizeof(area_struct));
		memset(new_area, 0, sizeof(area_struct));
		tosearch->next = new_area;
		new_area->addr =
		    last_user->addr + last_user->size * PAGE_SIZE;
		if (new_area->addr + num_pages * PAGE_SIZE >= kernel_lowest_addr) {
			/* Out of virtual memory, return */
			/* This if statement is critical, so its impossible for attackers to exploit the vmm to map over the kernel */
			/* (therefor crashing the OS) */
			return NULL;
		}
		new_area->size = num_pages;
		new_area->type = PAGE_RAM | PAGE_USER;
		new_area->protection = PAGE_RW;
		new_area->is_used = true;
		return (void *) new_area->addr;
	}
}

void vmm_free_addr(void *address)
{
	if (!address)
		return;
	area_struct *tosearch = first;
	while (1) {
		if (tosearch->addr == (uintptr_t) address) {
			tosearch->is_used = false;
			return;
		}
		tosearch = tosearch->next;
	}
}

int vmm_mark_addr_as_used(void *address, size_t pages)
{
	uint32_t addr = (uint32_t) address;

	area_struct *tosearch = first;
	while (1) {
		if (tosearch->addr == (uintptr_t) addr) {
			if (tosearch->is_used == true)
				return 1;
			if (tosearch->size < pages)
				return 1;
			tosearch->is_used = true;
			return 0;
		}
		if (tosearch->next == NULL)
			break;
		tosearch = tosearch->next;
	}
	area_struct *area = kmalloc(sizeof(area_struct));
	area->addr = addr;
	area->size = pages;
	area->type = PAGE_RAM | PAGE_USER;
	area->protection = PAGE_RW;
	area->is_used = true;
	tosearch->next = area;
	return 0;
}
pdirectory *_vmm_fork()
{
	/*Get the current page directory */
	pdirectory *tobeforked = get_directory();
	/* if there is none,return */
	if (!tobeforked)
		return NULL;
	pdirectory *newdir = (pdirectory *) valloc(1,true);
	/* Copy the page directory to a new address */
	memcpy((void *) newdir, (void *) tobeforked, sizeof(pdirectory));

	for (int i = 0; i < 1024; i++) {
		if (pd_entry_is_present(newdir->entries[i]) && i < 768
		    && i != 0) {
			/* Signal Copy-on-Write */
			SET_BIT(newdir->entries[i], 10);
			SET_BIT(newdir->entries[i], 9);
			SET_BIT(tobeforked->entries[i], 10);
			SET_BIT(tobeforked->entries[i], 9);
			/*Use COW (Copy-on-Write) */
			pd_entry_unset_bit(&newdir->entries[i],
					   _PDE_WRITABLE);
			pd_entry_unset_bit(&tobeforked->entries[i],
					   _PDE_WRITABLE);
		}
	}
	pdirectory *pnewdir = get_phys_addr(tobeforked, (uintptr_t)newdir);
	vfree(newdir,1);
	void *ptr = NULL;
	while(ptr != pnewdir)
	{
		ptr = pmalloc(1);
	}
	return pnewdir;
}

void *get_phys_addr(pdirectory *dir, uint32_t virt)
{
	pd_entry *entry = &dir->entries[PAGE_DIRECTORY_INDEX(virt)];
	if (pd_entry_is_4MB(*entry)) {
		return (void *) pd_entry_pfn(*entry);
	} else {
		ptable *pt = (ptable *) (0xFFC00000 + (virt / 0x400000 * 0x1000));
		pt_entry *page = &pt->entries[PAGE_TABLE_INDEX(virt)];
		return (void *) pt_entry_pfn(*page);
	}
}
int vmm_alloc_cow(uintptr_t address)
{
	pdirectory *dir = get_directory();
	if (!dir)
		abort();

	pd_entry *entry = &dir->entries[PAGE_DIRECTORY_INDEX(address)];
	/* TODO: Complete the implementation */
	if (!(TEST_BIT(*entry, 10)) && TEST_BIT(*entry, 9))
	{
		return 1;
	}
	if (pd_entry_is_4MB(*entry)) {
		char *mem = kmmap(0xD0000000,1024, MAP_USER | MAP_WRITE);
		if(!mem)
			panic("Kernel address space out of memory");

		/* Align the pointer to the nearest 4mb page */
		void *aligned_ptr = (void *) (address - (address % 0x400000));
		memcpy(mem, aligned_ptr, 0x400000);
		pd_entry_set_frame(entry, (uint32_t)get_phys_addr(get_directory(),(uint32_t)mem));
		pd_entry_set_bit(entry, _PDE_WRITABLE);
		/* TODO: Put a spinlock right here */
		kmunmap(mem, 1024);
		pmalloc(1024);
	} else {
		void *new_page = valloc(1,true);
		memcpy(new_page, (void *) address, 4096);
		uint32_t new_frame =
		    (uint32_t) get_phys_addr(dir, (uint32_t) new_page);
		if(!new_frame)
			panic("New frame == NULL");
		ptable *pt = (ptable *) (0xFFC00000 + (address / 0x400000 * 0x1000));
		if(pt_entry_is_writable(pt->entries[PAGE_TABLE_INDEX(address)])) {
			/* Already COW'ed*/
			return 0;
		}
		pt_entry_set_frame(&pt->entries[PAGE_TABLE_INDEX(address)],
				   new_frame);
		pt_entry_set_bit(&pt->entries[PAGE_TABLE_INDEX(address)],_PTE_WRITABLE);
		/* NOT SMP SAFE */
		vfree(new_page, 1);
		pmalloc(1);
	}
	return 0;
}
