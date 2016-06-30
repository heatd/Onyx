/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <kernel/paging.h>

inline uint64_t make_pml4e(uint64_t base,uint64_t avl,uint64_t pcd,uint64_t pwt,uint64_t us,uint64_t rw,uint64_t p)
{
	return (uint64_t)( \
  		(base) | \
  		(avl << 9) | \
  		(pcd << 4) | \
  		(pwt << 3) | \
  		(us << 2) | \
  		(rw << 1) | \
  		p);
}
inline uint64_t make_pml3e(uint64_t base,uint64_t nx, uint64_t avl,uint64_t glbl,uint64_t pcd,uint64_t pwt,uint64_t us,uint64_t rw,uint64_t p)
{
	return (uint64_t)( \
  		(base) | \
  		(nx << 63) | \
  		(avl << 9) | \
  		(glbl << 8) | \
  		(pcd << 4) | \
  		(pwt << 3) | \
  		(us << 2) | \
  		(rw << 1) | \
  		p);
}
inline uint64_t make_pml2e(uint64_t base,uint64_t nx, uint64_t avl,uint64_t glbl,uint64_t pcd,uint64_t pwt,uint64_t us,uint64_t rw,uint64_t p)
{
	return (uint64_t)( \
  		(base) | \
  		(nx << 63) | \
  		(avl << 9) | \
  		(glbl << 8) | \
  		(pcd << 4) | \
  		(pwt << 3) | \
  		(us << 2) | \
  		(rw << 1) | \
  		p);
}
inline uint64_t make_pml1e(uint64_t base,uint64_t nx, uint64_t avl,uint64_t glbl,uint64_t pcd,uint64_t pwt,uint64_t us,uint64_t rw,uint64_t p)
{
	return (uint64_t)( \
  		(base) | \
  		(nx << 63) | \
  		(avl << 9) | \
  		(glbl << 8) | \
  		(pcd << 4) | \
  		(pwt << 3) | \
  		(us << 2) | \
  		(rw << 1) | \
  		p);
}

typedef struct {
    uint64_t offsetFromPage :12;
    uint64_t pt :9;
    uint64_t pd :9;
    uint64_t pdpt :9;
    uint64_t pml4 :9;
    uint64_t rest :16;
} decomposed_addr_t;
static PML4 *current_pml4 = NULL;
void paging_init()
{
	/* Get the current PML4 and store it */
	asm volatile("movq %%cr3, %%rax\t\nmovq %%rax, %0":"=r"(current_pml4));
}
void paging_map_all_phys(size_t memInBytes)
{
	uintptr_t virt = 0xFFFFA00000000000;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	uint64_t* entry = &current_pml4->entries[decAddr.pml4];
	PML3* pml3 = NULL;
	/* If its present, use that pml3 */
	if(*entry & 1) {
		pml3 = (PML3*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else { /* Else create one */
		pml3 = (PML3*)pmalloc(1);
		if(!pml3)
			return;
		memset(pml3, 0, sizeof(PML3));
		*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, 0, 1, 1);
	}
	for(size_t mapped = 0, i = 0; mapped < memInBytes;mapped+=0x40000000, i++)
	{
		entry = &pml3->entries[i];
		*entry = make_pml3e(mapped, 1, 0, 1, 0, 0, 0, 1, 1);
		*entry |= (1 << 7);
	}

}
void* paging_map_phys_to_virt(uint64_t virt, uint64_t phys, uint64_t prot)
{
	_Bool user = 0;
	if (virt < 0x00007fffffffffff)
		user = 1;
	if(!current_pml4)
		return NULL;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	PML4 *pml4 = (PML4*)((uint64_t)current_pml4 + PHYS_BASE);
	uint64_t* entry = &pml4->entries[decAddr.pml4];
	PML3* pml3 = NULL;
	PML2* pml2 = NULL;
	PML1* pml1 = NULL;
	/* If its present, use that pml3 */
	if(*entry & 1) {
		pml3 = (PML3*)(*entry & 0x0FFFFFFFFFFFF000 );
	}
	else { /* Else create one */
		pml3 = (PML3*)pmalloc(1);
		if(!pml3)
			return NULL;
		memset((void*)((uint64_t)pml3 + PHYS_BASE), 0, sizeof(PML3));
		*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, user ? 1 : 0, 1, 1);
	}
	pml3 = (PML3*)((uint64_t)pml3 + PHYS_BASE);
	entry = &pml3->entries[decAddr.pdpt];
	if(*entry & 1) {
		pml2 = (PML2*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else {
		pml2 = (PML2*)pmalloc(1);
		if(!pml2 )
			return NULL;
		memset((void*)((uint64_t)pml2 + PHYS_BASE), 0, sizeof(PML2));
		*entry = make_pml3e( (uint64_t)pml2, 0, 0, 0, 0, 0, user ? 1 : 0, 1, 1);
	}
	pml2 = (PML2*)((uint64_t)pml2 + PHYS_BASE);
	entry = &pml2->entries[decAddr.pd];
	if(*entry & 1) {
		pml1 = (PML1*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else {
		pml1 = (PML1*)pmalloc(1);
		if(!pml1)
			return NULL;
		memset((void*)((uint64_t)pml1 + PHYS_BASE), 0, sizeof(PML1));
		*entry = make_pml2e( (uint64_t)pml1, (prot & 4), 0, (prot & 2)? 1 : 0, 0, 0, (prot & 0x80) ? 1 : 0, (prot & 1)? 1 : 0, 1);
	}
	pml1 = (PML1*)((uint64_t)pml1 + PHYS_BASE);
	entry = &pml1->entries[decAddr.pt];
	*entry = make_pml1e( phys, (prot & 4) ? 1 : 0, 0, (prot & 0x2) ? 1 : 0, 0, 0, (prot & 0x80) ? 1 : 0, (prot & 1) ? 1 : 0, 1);
	return (void*)virt;
}
void paging_unmap(void* memory, size_t pages)
{
	(void) memory;
	(void) pages;
}
