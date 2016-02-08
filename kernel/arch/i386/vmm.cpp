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


extern "C" void loadPageDirectory(pdirectory*);
extern "C" void enablePaging();

int alloc_page(pt_entry* pt)
{
	void* p = pmalloc(1);
	if(!p)
		return 1;
	pt_entry_set_frame(pt,(uintptr_t)p);
	pt_entry_set_bit(pt,_PTE_PRESENT);

	return 0;
}
void free_page(pt_entry* pt)
{
	void* p = (void*)pt_entry_pfn(*pt);
	if(p)
		pfree(1,p);

	pt_entry_unset_bit(pt,_PTE_PRESENT);
}
inline pt_entry* ptable_lookup_entry (ptable* p,virtual_addr addr) {

	if (p)
		return &p->entries[ PAGE_TABLE_INDEX (addr) ];
	return 0;
}
inline pd_entry* pdirectory_lookup_entry (pdirectory* p, virtual_addr addr) {

	if (p)
		return &p->entries[ PAGE_TABLE_INDEX (addr) ];
	return 0;
}
pdirectory*		_cur_directory=0;

int switch_directory (pdirectory* dir) {

	if (!dir)
		return 1;
        _cur_directory = dir;
	loadPageDirectory(_cur_directory);
	return 0;
}

pdirectory* get_directory () {

	void* ret = _cur_directory + 0xC0000000;
	return (pdirectory*)ret;
}

void init_vmm()
{
	ptable* mb = (ptable*)0xC03F0000;
	memset(mb,0,sizeof(ptable));
        ptable* table = (ptable*)0xC03F1000;
        memset(table, 0,sizeof(ptable));

	for(int i=0,frame=0x000000,virt=0x00000000;i<1024;i++,frame+=4096, virt+=4096)
	{
		pt_entry page=0;
		pt_entry_set_bit(&page,_PTE_PRESENT);
		pt_entry_set_bit(&page,_PTE_USER);
		pt_entry_set_frame(&page, frame);

		mb->entries [PAGE_TABLE_INDEX(virt)] = page;
        }
	for(int i=0,frame=0x000000,virt=0xC0000000;i<1024;i++,frame+=4096, virt+=4096)
	{
		pt_entry page=0;
		pt_entry_set_bit(&page,_PTE_PRESENT);
		pt_entry_set_bit(&page,_PTE_USER);
		pt_entry_set_frame(&page, frame);

		table->entries [PAGE_TABLE_INDEX(virt)] = page;
        }
	pdirectory* dir = (pdirectory*)0xC03F2000;
	memset(dir, 0,sizeof(pdirectory));
	pd_entry* entry =&dir->entries [PAGE_DIRECTORY_INDEX (0xC0000000)];
        pd_entry_set_bit (entry,_PDE_PRESENT);
        pd_entry_set_bit (entry,_PDE_WRITABLE);
	pd_entry_set_bit (entry, _PDE_USER);
        table=(ptable*)0x3F0000;
        pd_entry_set_frame(entry,(uintptr_t)table);
	pd_entry* entry2 = &dir->entries[PAGE_DIRECTORY_INDEX(0)];
	pd_entry_set_bit(entry2,_PDE_PRESENT);
	pd_entry_set_bit(entry2,_PDE_WRITABLE);
	pd_entry_set_bit(entry2,_PTE_USER);
	mb = (ptable*) 0x3F1000;
	pd_entry_set_frame(entry2,(uintptr_t)mb);
	pd_entry* entry3 = &dir->entries[PAGE_DIRECTORY_INDEX(0xFFC00000)];
        pd_entry_set_bit(entry3,_PDE_PRESENT);
        pd_entry_set_bit(entry3,_PDE_WRITABLE);
	dir = (pdirectory*) 0x3F2000;
	pd_entry_set_frame(entry3,(uintptr_t)dir);
        switch_directory(dir);
}
void* kmmap(uint32_t virt, DWORD npages)
{
	if (!npages)
		return NULL;
	pdirectory* pdir = get_directory();
	if (!pdir)
		abort();
	if(npages > 1024)
		npages = 1024;
	pd_entry* entry = &pdir->entries[PAGE_DIRECTORY_INDEX(virt)];
	ptable* pt = NULL;
	if(pd_entry_is_4MB(*entry) == 1 && pd_entry_pfn(*entry) != NULL)
		return NULL;
	
	if(npages == 1024){
		pd_entry_set_bit(entry,_PDE_PRESENT);
		pd_entry_set_bit(entry,_PDE_WRITABLE);
		pd_entry_set_bit(entry,_PDE_4MB);
		void* ptr = pmalloc(1024);
		pd_entry_set_frame(entry,(uintptr_t)ptr);
		return ptr;
		
	}
	if (pd_entry_is_present(*entry))
		pt = (ptable*)pd_entry_pfn(*entry);
	else {
		pt = (ptable*)pmalloc(1);
		if(pt == NULL)
			panic("No free blocks");
		memset(pt, 0, sizeof(ptable));
		pd_entry_set_bit(entry, _PDE_PRESENT);
		pd_entry_set_bit(entry, _PDE_WRITABLE);
		pd_entry_set_frame(entry, (uintptr_t)pt);
	}
	uint32_t ret_addr = 0;
	for (int i = 0, vaddr = virt; i<npages; i++, vaddr+=4096) {
	if (i == 0)
		ret_addr = vaddr;
        // create a new page
		pt_entry page=0;
		if(alloc_page(&page)==1){
			printf("Failed to map page 0x%x\n",vaddr);
			panic("No more physical memory");
		}
		//...and add it to the page table
		pt->entries [PAGE_TABLE_INDEX (vaddr) ] = page;
	}
	return (void*)ret_addr;
}

void kmunmap(void* virt, DWORD npages)
{
	if (!virt)
		return;
	if (!npages)
		return;
	pdirectory* pdir = get_directory();
	if (!pdir)
		return;
	pd_entry* entry = &pdir->entries[PAGE_DIRECTORY_INDEX((uint32_t)virt)];
	if (!pd_entry_is_present(*entry))
		return;
	ptable* pt = (ptable*)pd_entry_pfn(*entry);
	if ( !pt_entry_is_present(pt->entries[PAGE_TABLE_INDEX((uint32_t)virt)]))
	 return;
	for (DWORD i = 0, vaddr = (DWORD)virt; i<npages;i++, vaddr += 4096){

		pt_entry* page = &pt->entries [PAGE_TABLE_INDEX(vaddr)];
		free_page(page);
		_flush_tlb_page(vaddr);
	}

}
void* vmalloc(DWORD npages)
{
	if(!npages)
		return NULL;
	void* ptr = pmalloc(npages);
	if(!ptr)
		return NULL;
	pfree(npages,ptr);
	if(!kmmap((uint32_t)ptr,npages))
		return NULL;
	return ptr;
}

void vfree(void* ptr, DWORD npages)
{
	if(!npages)
		return;
	if(!ptr)
		return;
	kmunmap(ptr,npages);
}

void map_kernel()
{
	ptable* table = (ptable*)vmalloc(1);
	
	for(int i=0,frame=0x000000,virt=0xC0000000;i<1024;i++,frame+=4096, virt+=4096)
	{
		pt_entry page=0;
		pt_entry_set_bit(&page,_PTE_PRESENT);
		pt_entry_set_frame(&page, frame);
		table->entries [PAGE_TABLE_INDEX(virt)] = page;
        }
        pdirectory* pd = get_directory();
	if(!pd)
		abort();
	pd_entry* entry = &pd->entries[PAGE_DIRECTORY_INDEX(0xC0000000)];
	pd_entry_set_frame(entry,(uintptr_t)table);
	pd_entry_set_bit(entry, _PDE_PRESENT);
	pd_entry_set_bit(entry, _PDE_WRITABLE);
}