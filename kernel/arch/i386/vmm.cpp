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
#include <stddef.h>
#include <string.h>
#include <kernel/pmm.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <kernel/panic.h>
//! virtual address
typedef uint32_t virtual_addr;
static VMM::area_struct* first = nullptr;
extern "C" void loadPageDirectory(VMM::pdirectory*);
extern "C" void enablePaging();
using namespace VMM;

static int alloc_page(VMM::pt_entry* pt)
{
	void* p = pmalloc(1);
	if(!p)
		return 1;
	pt_entry_set_frame(pt,(uintptr_t)p);
	pt_entry_set_bit(pt,_PTE_PRESENT);

	return 0;
}
static void free_page(VMM::pt_entry* pt)
{
	void* p = (void*)pt_entry_pfn(*pt);
	if(p)
		pfree(1,p);

	pt_entry_unset_bit(pt,_PTE_PRESENT);
}
inline VMM::pt_entry* ptable_lookup_entry (VMM::ptable* p,virtual_addr addr) {

	if (p)
		return &p->entries[ PAGE_TABLE_INDEX (addr) ];
	return 0;
}
inline VMM::pd_entry* pdirectory_lookup_entry (VMM::pdirectory* p, virtual_addr addr) {

	if (p)
		return &p->entries[ PAGE_TABLE_INDEX (addr) ];
	return 0;
}
VMM::pdirectory*		_cur_directory=0;

int switch_directory (VMM::pdirectory* dir)
{

	if (!dir)
		return 1;
        _cur_directory = dir;
	loadPageDirectory(_cur_directory);
	return 0;
}

VMM::pdirectory* get_directory () {

	void* ret = _cur_directory;
	return (VMM::pdirectory*)ret;
}

void VMM::Init(uint32_t framebuffer_addr)
{
	ptable* mb = (ptable*)0xC03F0000;
	memset(mb,0,sizeof(ptable));
        ptable* table = (ptable*)0xC03F1000;
        memset(table, 0,sizeof(ptable));
	ptable* framebuffer = (ptable*)0xC03F3000;
	memset(table,0, sizeof(ptable));
	for(int i=0,frame=0,virt=0;i<1024;i++,frame+=4096, virt+=4096)
	{
		pt_entry page=0;
		pt_entry_set_bit(&page,_PTE_PRESENT);
		pt_entry_set_frame(&page, frame);
		if(virt == 0)
			pt_entry_unset_bit(&page,_PTE_PRESENT);
		mb->entries [PAGE_TABLE_INDEX(virt)] = page;
        }
	for(int i=0,frame=framebuffer_addr,virt=framebuffer_addr;i<1024;i++,frame+=4096, virt+=4096)
	{
		pt_entry page=0;
		pt_entry_set_bit(&page,_PTE_PRESENT);
		pt_entry_set_frame(&page, frame);
		framebuffer->entries [PAGE_TABLE_INDEX(virt)] = page;
        }
	for(int i=0,frame=0x000000,virt=0xC0000000;i<1024;i++,frame+=4096, virt+=4096)
	{
		pt_entry page=0;
		pt_entry_set_bit(&page,_PTE_PRESENT);
		pt_entry_set_frame(&page, frame);

		table->entries [PAGE_TABLE_INDEX(virt)] = page;
        }
	pdirectory* dir = (pdirectory*)0xC03F2000;
	memset(dir, 0,sizeof(pdirectory));
	pd_entry* entry =&dir->entries [PAGE_DIRECTORY_INDEX (0xC0000000)];
        pd_entry_set_bit (entry,_PDE_PRESENT);
        pd_entry_set_bit (entry,_PDE_WRITABLE);
        table=(ptable*)0x3F0000;
        pd_entry_set_frame(entry,(uintptr_t)table);
	pd_entry* entry2 = &dir->entries[PAGE_DIRECTORY_INDEX(0)];
	pd_entry_set_bit(entry2,_PDE_PRESENT);
	pd_entry_set_bit(entry2,_PDE_WRITABLE);
	mb = (ptable*) 0x3F1000;
	pd_entry_set_frame(entry2,(uintptr_t)mb);
	pd_entry* entry3 = &dir->entries[PAGE_DIRECTORY_INDEX(0xFFC00000)];
        pd_entry_set_bit(entry3,_PDE_PRESENT);
        pd_entry_set_bit(entry3,_PDE_WRITABLE);
	pd_entry* framebuf = &dir->entries[PAGE_DIRECTORY_INDEX(framebuffer_addr)];
	pd_entry_set_bit(framebuf,_PDE_PRESENT);
	pd_entry_set_bit(framebuf,_PDE_WRITABLE);
	framebuffer = (ptable*) 0x3F3000;
	pd_entry_set_frame(framebuf,(uintptr_t)framebuffer);
	dir = (pdirectory*) 0x3F2000;
	pd_entry_set_frame(entry3,(uintptr_t)dir);
        switch_directory(dir);
}
// Finish installing the VMM
void VMM::Finish()
{
	first = new area_struct;
	first->addr = 0x0;
	first->size = 1024;
	first->is_used = true;
	first->type = PAGE_RAM | PAGE_KERNEL;
	first->protection = PAGE_RW;
	area_struct* area = new area_struct;
	first->next = area;
	area->addr = 0xC0000000;
	area->size = 3840;
	area->type = PAGE_RAM | PAGE_KERNEL;
	area->protection = PAGE_RWE;
	area->is_used = true;
	area->next = nullptr;

}
void* kmmap(uint32_t virt, uint32_t npages, uint32_t flags)
{
	uint32_t vaddr = virt;
	if(npages > 1024)
	{
		uint32_t number_of_allocs = npages / 1024;
		for(int i = 0; i < number_of_allocs; i++)
		{
			VMM::Map(virt,1024,flags);
			vaddr+=4096 * PAGE_SIZE;
		}
		VMM::Map(vaddr,npages % 1024,flags);
	}
	else
		VMM::Map(vaddr,npages,flags);
	return (void*)vaddr;
}
void* VMM::Map(uint32_t virt, uint32_t npages,uint32_t flags)
{
	if (!npages)
		return nullptr;
	VMM::pdirectory* pdir = get_directory();
	if (!pdir)
		abort();
	if(npages > 1024)
		npages = 1024;
	VMM::pd_entry* entry = &pdir->entries[PAGE_DIRECTORY_INDEX(virt)];
	VMM::ptable* pt = nullptr;
	if(pd_entry_is_4MB(*entry) == 1 && pd_entry_pfn(*entry) != NULL)
		return nullptr;

	if(npages == 1024){
		pd_entry_set_bit(entry,_PDE_PRESENT);
		pd_entry_set_bit(entry,flags);
		pd_entry_set_bit(entry,_PDE_4MB);
		void* ptr = pmalloc(1024);
		pd_entry_set_frame(entry,(uintptr_t)ptr);
		return ptr;
	}
	if (pd_entry_is_present(*entry))
		pt = (VMM::ptable*)pd_entry_pfn(*entry);
	else {
		pt = (VMM::ptable*)pmalloc(1);
		if(!pt)
			panic("No free blocks");
		kmmap((uint32_t)pt,1024,_PDE_WRITABLE);
		memset(pt, 0, sizeof(VMM::ptable));
		pd_entry_set_bit(entry, _PDE_PRESENT);
		pd_entry_set_bit(entry,flags);
		pd_entry_set_frame(entry, (uintptr_t)pt);
	}
	uint32_t ret_addr = 0;
	for (int i = 0, vaddr = virt; i<npages; i++, vaddr+=4096)
	{
		if (i == 0)
			ret_addr = vaddr;
      		// create a new page
		VMM::pt_entry page=0;
		if(alloc_page(&page) == 1)
		{
			printf("Failed to map page 0x%X\n",vaddr);
			panic("No more physical memory");
		}
		pt_entry_set_bit(entry,flags);
		//...and add it to the page table
		pt->entries [PAGE_TABLE_INDEX (vaddr) ] = page;
	}
	return (void*)ret_addr;
}

void kmunmap(void* virt, uint32_t npages)
{
	if (!virt)
		return;
	if (!npages)
		return;
	VMM::pdirectory* pdir = get_directory();
	if (!pdir)
		return;
	VMM::pd_entry* entry = &pdir->entries[PAGE_DIRECTORY_INDEX((uint32_t)virt)];
	if (!pd_entry_is_present(*entry))
		return;
	VMM::ptable* pt = (VMM::ptable*)pd_entry_pfn(*entry);
	if ( !pt_entry_is_present(pt->entries[PAGE_TABLE_INDEX((uint32_t)virt)]))
		return;
	for (DWORD i = 0, vaddr = (DWORD)virt; i<npages;i++, vaddr += 4096){

		VMM::pt_entry* page = &pt->entries [PAGE_TABLE_INDEX(vaddr)];
		free_page(page);
		_flush_tlb_page(vaddr);
	}
	for(uint32_t i = 0;i < 1024;i++) //Optimization
	{
		if(pt_entry_is_present(pt->entries[i]))
			break;
		else if(i == 1024)
			kmunmap((void*)pt,1);
	}
}
void* VMM::AllocateAddress(size_t num_pages,bool is_kernel)
{
	uint32_t placement_addr = 0;
	if(is_kernel)
	{
		area_struct* tosearch = first;
		area_struct* last_kernel = first;
		// Search the linked list
		while(1)
		{
			if(tosearch->addr >= kernel_lowest_addr)
			{
				last_kernel = tosearch;
				if(last_kernel->size >= num_pages && last_kernel->is_used == false)
				{
					placement_addr = last_kernel->addr;
					last_kernel->is_used = true;
					return (void*)last_kernel->addr;
				}
			}
			if(tosearch->next == nullptr)
				break;
			tosearch = tosearch->next;
		}
		area_struct* new_area = new area_struct;
		memset(new_area,0,sizeof(area_struct));
		tosearch->next = new_area;
		new_area->addr = last_kernel->addr + last_kernel->size * PAGE_SIZE;
		if(new_area->addr + num_pages * PAGE_SIZE >= 0xFFC00000)
		{
			// Out of virtual memory, return
			// This if statement is critical, so its impossible for attackers to exploit the vmm to map over the recursive mapping
			return nullptr;
		}
		new_area->size = num_pages;
		new_area->type = PAGE_RAM | PAGE_KERNEL;
		new_area->protection = PAGE_RW;
		new_area->is_used = true;
		return (void*)new_area->addr;
	}
	else // If is_kernel != true, then the pages are going to be user accessible
	{
		area_struct* tosearch = first;
		area_struct* last_user = first;
		// Search the linked list
		while(1)
		{
			if(tosearch->addr >= user_lowest_addr)
			{
				last_user = tosearch;
				if(last_user->size >= num_pages && last_user->is_used == false)
				{
					placement_addr = last_user->addr;
					last_user->is_used = true;
					return (void*)last_user->addr;
				}
			}
			if(tosearch->next == nullptr)
				break;
			tosearch = tosearch->next;
		}
		area_struct* new_area = new area_struct;
		memset(new_area,0,sizeof(area_struct));
		tosearch->next = new_area;
		new_area->addr = last_user->addr + last_user->size * PAGE_SIZE;
		if(new_area->addr + num_pages * PAGE_SIZE >= 0x80000000)
		{
			// Out of virtual memory, return
			// This if statement is critical, so its impossible for attackers to exploit the vmm to map over the kernel
			// (therefor crashing the OS)
			return nullptr;
		}
		new_area->size = num_pages;
		new_area->type = PAGE_RAM | PAGE_USER;
		new_area->protection = PAGE_RW;
		new_area->is_used = true;
		return (void*)new_area->addr;
	}
}
void VMM::FreeAddress(void* address)
{
	if(!address)
		return;
	area_struct* tosearch = first;
	while(1)
	{
		if(tosearch->addr == (uintptr_t)address)
		{
			tosearch->is_used = false;
			return;
		}
		tosearch = tosearch->next;
	}
}
void* valloc(uint32_t npages)
{
	if(!npages)
		return nullptr;
	void* vaddr = VMM::AllocateAddress(npages,true);
	if(!kmmap((uint32_t)vaddr,npages,_PDE_WRITABLE))
		return nullptr;
	return vaddr;
}

void vfree(void* ptr, uint32_t npages)
{
	if(!npages)
		return;
	if(!ptr)
		return;
	kmunmap(ptr,npages);
	VMM::FreeAddress(ptr);
}
void* VMM::IdentityMap(uint32_t addr,uint32_t npages)
{
	pdirectory* dir = get_directory();
	ptable* table = (ptable*)pmalloc(1);
	memset((void*)table,0,sizeof(ptable));
	for(int i, virt = addr;i < npages;i++,addr+=4096)
	{
		pt_entry page = 0;
		pt_entry_set_bit(&page,_PTE_PRESENT);
		pt_entry_set_bit(&page,_PTE_WRITABLE);
		pt_entry_set_frame(&page,virt);
		table->entries[PAGE_TABLE_INDEX(virt)] = page;
	}
	pd_entry* entry = &dir->entries[PAGE_DIRECTORY_INDEX(addr)];
	pd_entry_set_bit(entry,_PDE_PRESENT);
	pd_entry_set_bit(entry,_PDE_WRITABLE);
	pd_entry_set_frame(entry,(uintptr_t)table);
	return (void*)addr;
}
VMM::pdirectory* VMM::CreateAddressSpace()
{
	pdirectory* newpd = (pdirectory*)valloc(1);
	//STUB
}
VMM::pdirectory* VMM::CopyAddressSpace()
{
	//Get the current page directory
	VMM::pdirectory* tobeforked = get_directory();
	// if there is none,return
	if(!tobeforked)
		return nullptr;
	// Copy the page directory to a new address
	VMM::pdirectory* newdir = (VMM::pdirectory*)valloc(1);
	memcpy((void*)newdir,(void*)tobeforked,sizeof(VMM::pdirectory));

	for(int i = 0;i < 1024; i++)
	{
		if(newdir->entries[i] == NULL)
			continue;
		VMM::pd_entry* entry = &newdir->entries[i];
		if(pd_entry_is_4MB(*entry))
		{
			void* newmem = valloc(1024);
			memcpy(newmem,(const void*)pd_entry_pfn(newdir->entries[i]),1024 * 4096);
			kmunmap((void*)newmem,1024);
		}
		void* newtable = valloc(1);
		memcpy(newtable,(const void*)pd_entry_pfn(newdir->entries[i]),sizeof(VMM::ptable));
		VMM::ptable* pt = (VMM::ptable*)newtable;
		for(int j = 0; j < 1024; j++)
		{
			if(pt->entries[i] == NULL )
				continue;
			void* newphys = valloc(1);
			pt_entry_set_frame(&pt->entries[i],(uintptr_t)newphys);
			memcpy(newphys,(void*)(j * 0x400000),4096); // Copy the contents to a new page
			kmunmap((void*)newphys,1);
		}
		kmunmap((void*)newtable,1);
	}
	kmunmap((void*)newdir,1);
	return (VMM::pdirectory*)newdir;
}
