/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdbool.h>
#include <cpuid.h>
#include <assert.h>

#include <onyx/page.h>
#include <onyx/paging.h>
#include <onyx/process.h>
#include <onyx/vm.h>
#include <onyx/panic.h>
#include <onyx/cpu.h>

#include <onyx/x86/pat.h>

#define PML_EXTRACT_ADDRESS(n) (n & 0x0FFFFFFFFFFFF000)
#define X86_PAGING_PRESENT		(1 << 0)
#define X86_PAGING_WRITE		(1 << 1)
#define X86_PAGING_SUPERVISOR		(1 << 2)
#define X86_PAGING_HUGE			(1 << 7)
#define X86_PAGING_GLOBAL		(1 << 8)
#define X86_PAGING_NX			(1UL << 63)

static inline void __native_tlb_invalidate_page(void *addr)
{
	__asm__ __volatile__("invlpg %0"::"m"(addr));
}

static inline uint64_t make_pml4e(uint64_t base,
				  uint64_t avl,
				  uint64_t pcd,
				  uint64_t pwt,
				  uint64_t us,
				  uint64_t rw,
				  uint64_t p)
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

static inline uint64_t make_pml3e(uint64_t base,
				  uint64_t nx,
				  uint64_t avl,
				  uint64_t glbl,
				  uint64_t pcd,
				  uint64_t pwt,
				  uint64_t us,
				  uint64_t rw,
				  uint64_t p)
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

static inline uint64_t make_pml2e(uint64_t base,
				  uint64_t nx,
				  uint64_t avl,
				  uint64_t glbl,
				  uint64_t pcd,
				  uint64_t pwt,
				  uint64_t us,
				  uint64_t rw,
				  uint64_t p)
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

static inline uint64_t make_pml1e(uint64_t base,
				  uint64_t nx,
				  uint64_t avl,
				  uint64_t glbl,
				  uint64_t caching_bits,
				  uint64_t us,
				  uint64_t rw,
				  uint64_t p)
{
	return (uint64_t)(
  		(base) |
  		(nx << 63) |
  		(avl << 9) |
  		(glbl << 8) |
  		((caching_bits << 3) & 0x3) |
  		(us << 2) |
  		(rw << 1) |
  		p);
}

typedef struct 
{
	uint64_t offsetFromPage : 12;
	uint64_t pt : 9;
	uint64_t pd : 9;
	uint64_t pdpt :9;
	uint64_t pml4 :9;
	uint64_t rest :16;
} decomposed_addr_t;

void *alloc_pt(void)
{
	struct page *p = alloc_page(0);
	return p != NULL ? p->paddr : NULL;
}

PML4 *boot_pml4;

PML4 *get_current_pml4(void)
{
	struct process *p = get_current_process();
	if(!p)
		return boot_pml4;
	return (PML4*) p->address_space.cr3;
}

void *__virtual2phys(struct process *process, void *ptr)
{
	decomposed_addr_t dec;
	memcpy(&dec, &ptr, sizeof(decomposed_addr_t));
	PML4 *pml4 = PHYS_TO_VIRT(process ? process->address_space.cr3 : get_current_pml4());

	PML3 *pml3 = (PML3*)((pml4->entries[dec.pml4] & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	PML2 *pml2 = (PML2*)((pml3->entries[dec.pdpt] & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	PML1 *pml1 = (PML1*)((pml2->entries[dec.pd] & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	return (void *)((pml1->entries[dec.pt] & 0x0FFFFFFFFFFFF000) + dec.offsetFromPage);
}

void *virtual2phys(void *ptr)
{
	return __virtual2phys(NULL, ptr);
}

extern PML3 pdptphysical_map;
static PML2 pdphysical_map __attribute__((aligned(PAGE_SIZE)));
void paging_init(void)
{
	/* Get the current PML4 and store it */
	__asm__ __volatile__("movq %%cr3, %%rax\t\nmovq %%rax, %0":"=r"(boot_pml4));
	/* Bootstrap the first 1GB */
	uintptr_t virt = PHYS_BASE;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	uint64_t* entry = &get_current_pml4()->entries[decAddr.pml4];
	PML3* pml3 = (PML3*)&pdptphysical_map;
	
	memset(pml3, 0, sizeof(PML3));
	*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, 0, 1, 1);
	entry = &pml3->entries[decAddr.pdpt];
	*entry = make_pml3e(((uint64_t) &pdphysical_map - KERNEL_VIRTUAL_BASE), 0, 0, 1, 0, 0, 0, 1, 1);
	
	for(size_t j = 0; j < 512; j++)
	{
		if(!paging_map_phys_to_virt_large_early(virt + j * 0x200000, 
		j * 0x200000, VM_NOEXEC  | VM_WRITE))
			while(1);
	}

}

void paging_map_all_phys(void)
{
	bool is_1gb_supported = x86_has_cap(X86_FEATURE_PDPE1GB);

	uintptr_t virt = PHYS_BASE;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	uint64_t* entry = &get_current_pml4()->entries[decAddr.pml4];
	PML3* pml3 = (PML3*)&pdptphysical_map;
	
	memset(pml3, 0, sizeof(PML3));
	*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, 0, 1, 1);

	if(is_1gb_supported)
	{
		for(size_t i = 0; i < 512; i++)
		{
			entry = &pml3->entries[i];
			*entry = make_pml3e(i * 0x40000000, 0, 0, 1, 0, 0, 0, 1, 1);
			*entry |= X86_PAGING_HUGE;
			__native_tlb_invalidate_page((void*)(virt + i * 0x40000000));
		}
	}
	else
	{
		/* Use 2MiB pages instead */
		entry = &pml3->entries[decAddr.pdpt];
		*entry = make_pml3e(((uint64_t) &pdphysical_map - KERNEL_VIRTUAL_BASE), 0, 0, 1, 0, 0, 0, 1, 1);
		for(size_t i = 0; i < 512; i++)
		{
			for(size_t j = 0; j < 512; j++)
			{
				if(!paging_map_phys_to_virt_large(virt + i * 0x40000000 + j * 0x200000, 
				i * 0x40000000 + j * 0x200000, VM_NOEXEC  | VM_WRITE))
					return;
			}
		}
	}
}

void *paging_map_phys_to_virt_huge(uint64_t virt, uint64_t phys, uint64_t prot)
{
	_Bool user = 0;
	if (virt < 0x00007fffffffffff)
		user = 1;
	if(!get_current_pml4())
		return NULL;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	PML4 *pml4 = (PML4*)((uint64_t)get_current_pml4() + KERNEL_VIRTUAL_BASE);
	uint64_t* entry = &pml4->entries[decAddr.pml4];
	PML3* pml3 = NULL;
	if(*entry & X86_PAGING_PRESENT)
	{
		pml3 = (PML3*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else
	{
		pml3 = (PML3*) alloc_pt();
		if(!pml3)
			return NULL;
		memset((void*)((uint64_t)pml3 + KERNEL_VIRTUAL_BASE), 0, sizeof(PML3));
		*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, user ? 1 : 0, 1, 1);
	}
	pml3 = (PML3*)((char*) pml3 + KERNEL_VIRTUAL_BASE);
	pml3->entries[decAddr.pdpt] = make_pml3e((phys & 0x000fffffc0000000UL),
					(prot & VM_NOEXEC) ? 1 : 0, 0, 0, 0, 0,
					user ? 1 : 0, (prot & VM_WRITE) ? 1 : 0, 1);
	pml3->entries[decAddr.pdpt] |= X86_PAGING_HUGE;

	__native_tlb_invalidate_page((void*) virt);
	return (void*) virt;
}

void* paging_map_phys_to_virt_large_early(uint64_t virt, uint64_t phys, uint64_t prot)
{
	_Bool user = 0;
	if (virt < 0x00007fffffffffff)
		user = 1;
	if(!get_current_pml4())
		return NULL;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	PML4 *pml4 = (PML4*)((uint64_t)get_current_pml4() + KERNEL_VIRTUAL_BASE);
	
	uint64_t* entry = &pml4->entries[decAddr.pml4];
	PML3* pml3 = NULL;
	PML2* pml2 = NULL;
	/* If its present, use that pml3 */
	if(*entry & X86_PAGING_PRESENT) {
		pml3 = (PML3*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else { /* Else create one */
		pml3 = (PML3*) alloc_pt();
		if(!pml3)
			return NULL;
		memset((void*)((uint64_t)pml3 + KERNEL_VIRTUAL_BASE), 0, sizeof(PML3));
		*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, user ? 1 : 0, 1, 1);
	}
	pml3 = (PML3*)((uint64_t)pml3 + KERNEL_VIRTUAL_BASE);
	entry = &pml3->entries[decAddr.pdpt];
	if(*entry & X86_PAGING_PRESENT) {
		pml2 = (PML2*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else {
		pml2 = (PML2*) alloc_pt();
		if(!pml2)
			return NULL;
		memset((void*)((uint64_t)pml2 + KERNEL_VIRTUAL_BASE), 0, sizeof(PML2));
		*entry = make_pml3e( (uint64_t)pml2, 0, 0, 0, 0, 0, user ? 1 : 0, 1, 1);
	}
	pml2 = (PML2*)((uint64_t)pml2 + KERNEL_VIRTUAL_BASE);
	entry = &pml2->entries[decAddr.pd];
	
	*entry = make_pml2e(phys, (prot & 4), 0,
		 (prot & 2) ? 1 : 0, 0, 0, (prot & 0x80) ? 1 : 0,
		 (prot & 1)? 1 : 0, 1);
	*entry |= X86_PAGING_HUGE;
	return (void*) virt;
}

void* paging_map_phys_to_virt_large(uint64_t virt, uint64_t phys, uint64_t prot)
{
	bool user = 0;
	if (virt < 0x00007fffffffffff)
		user = 1;
	if(!get_current_pml4())
		return NULL;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	PML4 *pml4 = (PML4*)((uint64_t)get_current_pml4() + PHYS_BASE);
	
	uint64_t* entry = &pml4->entries[decAddr.pml4];
	PML3* pml3 = NULL;
	PML2* pml2 = NULL;
	/* If its present, use that pml3 */
	if(*entry & X86_PAGING_PRESENT)
	{
		pml3 = (PML3*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else
	{
		/* Else create one */
		pml3 = (PML3*) alloc_boot_page(1, 0);
		if(!pml3)
			return NULL;
		memset((void*)((uint64_t)pml3 + PHYS_BASE), 0, sizeof(PML3));
		*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, user ? 1 : 0, 1, 1);
	}
	
	pml3 = (PML3*)((uint64_t)pml3 + PHYS_BASE);
	entry = &pml3->entries[decAddr.pdpt];
	
	if(*entry & X86_PAGING_PRESENT)
	{
		pml2 = (PML2*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else
	{
		pml2 = (PML2*) alloc_boot_page(1, 0);
		if(!pml2)
			return NULL;
		memset((void*)((uint64_t)pml2 + PHYS_BASE), 0, sizeof(PML2));
		*entry = make_pml3e( (uint64_t)pml2, 0, 0, 0, 0, 0, user ? 1 : 0, 1, 1);
	}

	pml2 = (PML2*)((uint64_t)pml2 + PHYS_BASE);
	entry = &pml2->entries[decAddr.pd];
	
	*entry = make_pml2e(phys, (prot & 4), 0, (prot & 2)? 1 : 0, 0, 0, (prot & 0x80) ? 1 : 0, (prot & X86_PAGING_PRESENT)? 1 : 0, 1);
	*entry |= X86_PAGING_HUGE;
	return (void*) virt;
} 

volatile int test = 0;

void* paging_map_phys_to_virt(PML4 *__pml, uint64_t virt, uint64_t phys, uint64_t prot)
{
	bool user = 0;
	if (virt < 0x00007fffffffffff)
		user = 1;

	const unsigned int paging_levels = 4;
	unsigned int indices[paging_levels];

	for(unsigned int i = 0; i < paging_levels; i++)
	{
		indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
	}

	PML4 *pml = (PML4*)((uint64_t) __pml + PHYS_BASE);
	
	for(unsigned int i = paging_levels; i != 1; i--)
	{
		uint64_t entry = pml->entries[indices[i - 1]];
		if(entry & X86_PAGING_PRESENT)
		{
			void *page = (void*) PML_EXTRACT_ADDRESS(entry);
			pml = PHYS_TO_VIRT(page);
		}
		else
		{
			void *page = alloc_pt();
			memset(PHYS_TO_VIRT(page), 0, PAGE_SIZE);
			if(i == 3)
				pml->entries[indices[i - 1]] =
				make_pml4e((uint64_t) page, 0, 0, 0, user ? 1 : 0, 1, 1);
			else
				pml->entries[indices[i - 1]] =
				make_pml3e((uint64_t) page, 0, 0, 0, 0, 0, user ? 1 : 0,
						    1, 1);
			pml = PHYS_TO_VIRT(page);
		}
	}
	
	bool noexec = prot & VM_NOEXEC ? true : false;
	bool global = prot & VM_USER ? false : true;
	user = prot & VM_USER ? true : false;
	bool write = prot & VM_WRITE ? true : false;
	
	unsigned int cache_type = vm_prot_to_cache_type(prot);
	uint8_t caching_bits = cache_to_paging_bits(cache_type);

	pml->entries[indices[0]] = make_pml1e(phys, noexec, 0,
	global, caching_bits, user, write, 1);

	return (void*) virt;
}

bool pml_is_empty(void *_pml)
{
	PML1 *pml = _pml;
	for(int i = 0; i < 512; i++)
	{
		if(pml->entries[i])
			return false;
	}
	return true;
}

void *paging_unmap(void* memory)
{
	decomposed_addr_t dec;
	memcpy(&dec, &memory, sizeof(decomposed_addr_t));
	PML4 *pml4 = (PML4*)((uint64_t) get_current_pml4() + PHYS_BASE);
	
	uint64_t* entry = &pml4->entries[dec.pml4];

	if(!*entry & X86_PAGING_PRESENT)
		return NULL;
	PML3 *pml3 = (PML3*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml3->entries[dec.pdpt];
	if(!*entry & X86_PAGING_PRESENT) /* If the entry isn't committed, just return */
		return NULL;
	PML2 *pml2 = (PML2*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml2->entries[dec.pd];

	if(!*entry & X86_PAGING_PRESENT) /* If the entry isn't committed, just return */
		return NULL;
	PML1 *pml1 = (PML1*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml1->entries[dec.pt];

	if(!*entry & X86_PAGING_PRESENT) /* If the entry isn't committed, just return */
		return NULL;

	uintptr_t address = PML_EXTRACT_ADDRESS(*entry);
	*entry = 0;

	__native_tlb_invalidate_page(memory);
	/* Now that we've freed the destination page, work our way upwards to check if the paging structures are empty 
	   If so, free them as well 
	*/
	if(pml_is_empty(pml1))
	{
		//printk("Empty!\n");
		uintptr_t raw_address = pml2->entries[dec.pd] & 0x0FFFFFFFFFFFF000;
		free_page(phys_to_page(raw_address));
		pml2->entries[dec.pd] = 0;
	}

	if(pml_is_empty(pml2))
	{
		uintptr_t raw_address = pml3->entries[dec.pdpt] & 0x0FFFFFFFFFFFF000;
		free_page(phys_to_page(raw_address));
		pml3->entries[dec.pdpt] = 0;
	}

	if(pml_is_empty(pml3))
	{
		uintptr_t raw_address = pml4->entries[dec.pml4] & 0x0FFFFFFFFFFFF000;
		free_page(phys_to_page(raw_address));
		pml4->entries[dec.pml4] = 0;
	}

	return (void*) address;
}

int paging_clone_as(struct mm_address_space *addr_space)
{
	PML4 *new_pml = alloc_pt();
	if(!new_pml)
		return -1;
	PML4 *p = (PML4*)((uint64_t)new_pml + PHYS_BASE);
	memset(p, 0, sizeof(PML4));
	PML4 *curr = (PML4*)((uint64_t)get_current_pml4() + PHYS_BASE);
	/* Copy the upper 256 entries of the PML4 in order to map
	 * the kernel in the process's address space
	*/

	memcpy(&p->entries[256], &curr->entries[256], 256 * sizeof(uint64_t));

	addr_space->cr3 = new_pml;
	return 0;
}

static inline PML4 *paging_fork_pml(PML4 *pml, int entry)
{
	uint64_t old_address = PML_EXTRACT_ADDRESS(pml->entries[entry]);
	uint64_t perms = pml->entries[entry] & 0xF000000000000FFF;
	pml->entries[entry] = PML_EXTRACT_ADDRESS((uint64_t) alloc_pt()) | perms;
	PML4 *new_pml = (PML4*)((PML_EXTRACT_ADDRESS(pml->entries[entry])) + PHYS_BASE);
	PML4 *old_pml = (PML4*)(old_address + PHYS_BASE);
	memcpy(new_pml, old_pml, sizeof(PML4));
	return new_pml;
}

int paging_fork_tables(struct mm_address_space *addr_space)
{
	struct page *page = alloc_page(0);
	if(!page)
		return -1;
	PML4 *new_pml = page->paddr;
	PML4 *p = PHYS_TO_VIRT(new_pml);
	PML4 *curr = PHYS_TO_VIRT(get_current_pml4());
	memcpy(p, curr, sizeof(PML4));

	PML4 *mod_pml = (PML4*)((char*)new_pml + PHYS_BASE);
	/* TODO: Destroy the page tables on failure */
	for(int i = 0; i < 256; i++)
	{
		if(mod_pml->entries[i] & X86_PAGING_PRESENT)
		{
			PML3 *pml3 = (PML3*) paging_fork_pml(mod_pml, i);
			if(!pml3)
			{
				return -1;
			}

			for(int j = 0; j < PAGE_TABLE_ENTRIES; j++)
			{
				if(pml3->entries[j] & X86_PAGING_PRESENT)
				{
					PML2 *pml2 = (PML2*) paging_fork_pml((PML4*) pml3, j);
					if(!pml2)
					{
						return -1;
					}

					for(int k = 0; k < PAGE_TABLE_ENTRIES; k++)
					{
						if(pml2->entries[k] & X86_PAGING_PRESENT && !(pml2->entries[k] & (1<<7)))
						{
							PML1 *pml1 = (PML1*) paging_fork_pml((PML4*)pml2, k);
							if(!pml1)
							{
								return -1;
							}

						}
					}
				}
			}
		}
	}
	
	addr_space->cr3 = new_pml;
	return 0;
}

void paging_load_cr3(PML4 *pml)
{
	assert(pml != NULL);
	PML4 *oldpml;
	__asm__ __volatile__("movq %%cr3, %%rax\t\nmovq %%rax, %0":"=r"(oldpml));
	if(oldpml == pml)
		return;
	__asm__ __volatile__("movq %0, %%cr3"::"r"(pml));
}

void paging_change_perms(void *addr, int prot)
{
	decomposed_addr_t dec;
	memcpy(&dec, &addr, sizeof(decomposed_addr_t));
	PML4 *pml4 = (PML4*)((uint64_t)get_current_pml4() + PHYS_BASE);
	
	uint64_t* entry = &pml4->entries[dec.pml4];
	if(*entry == 0)
		return;
	PML3 *pml3 = (PML3*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml3->entries[dec.pdpt];
	if(*entry == 0)
		return;
	PML2 *pml2 = (PML2*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml2->entries[dec.pd];
	if(*entry == 0)
		return;
	PML1 *pml1 = (PML1*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml1->entries[dec.pt];
	if(*entry == 0)
		return;
	uint32_t perms = *entry & 0xF00000000000FFF;
	uint64_t page = PML_EXTRACT_ADDRESS(*entry);
	if(prot & VM_NOEXEC)
		perms |= X86_PAGING_NX;
	if(prot & VM_WRITE)
		perms |= X86_PAGING_WRITE;
	*entry = perms | page;
	__native_tlb_invalidate_page(addr);
}

int is_invalid_arch_range(void *address, size_t pages)
{
	for(uintptr_t addr = (uintptr_t) address, i = 0; i < pages; ++i, addr += PAGE_SIZE)
	{
		if(addr > 0x00007fffffffffff && addr < VM_HIGHER_HALF)
			return -1;
	}
	return 0;
}

void paging_walk(void *addr)
{
	decomposed_addr_t dec;
	memcpy(&dec, &addr, sizeof(decomposed_addr_t));
	PML4 *pml4 = (PML4*)((uint64_t)get_current_pml4() + PHYS_BASE);
	
	uint64_t* entry = &pml4->entries[dec.pml4];
	if(*entry == 0)
	{
		printk("isn't mapped(PML4 %p)\n", pml4);
		return;
	}
	PML3 *pml3 = (PML3*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml3->entries[dec.pdpt];
	if(*entry == 0)
	{
		printk("isn't mapped(PML3 %p)\n", pml3);
		return;
	}
	PML2 *pml2 = (PML2*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml2->entries[dec.pd];
	if(*entry == 0)
	{
		printk("isn't mapped(PML2 %p)\n", pml2);
		return;
	}
	PML1 *pml1 = (PML1*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml1->entries[dec.pt];
	if(*entry == 0)
	{
		printk("isn't mapped(PML1 %p)\n", pml1);
		return;
	}
	uint32_t perms = *entry & 0xF00000000000FFF;
	uint64_t page = PML_EXTRACT_ADDRESS(*entry);
	printk("Perms: %08x\nPage: %016lx\n", perms, page);
}

extern char _text_start;
extern char _text_end;
extern char _data_start;
extern char _data_end;
extern char _vdso_sect_start;
extern char _vdso_sect_end;
extern char VIRT_BASE;
extern struct mm_address_space kernel_address_space;

void paging_protect_kernel(void)
{
	PML4 *original_pml = boot_pml4;
	PML4 *pml = alloc_pt();
	boot_pml4 = pml;

	uintptr_t text_start = (uintptr_t) &_text_start;
	uintptr_t data_start = (uintptr_t) &_data_start;
	uintptr_t vdso_start = (uintptr_t) &_vdso_sect_start;

	memcpy((PML4*)((uintptr_t) pml + PHYS_BASE), (PML4*)((uintptr_t) original_pml + PHYS_BASE),
		sizeof(PML4));
	PML4 *p = (PML4*)((uintptr_t) pml + PHYS_BASE);
	p->entries[511] = 0UL;
	p->entries[0] = 0UL;
	map_pages_to_vaddr((void *) &VIRT_BASE, NULL, 0x100000, VM_WRITE | VM_NOEXEC);
	size_t size = (uintptr_t) &_text_end - text_start;
	map_pages_to_vaddr((void *) text_start, (void *) (text_start - KERNEL_VIRTUAL_BASE),
		size, 0);

	size = (uintptr_t) &_data_end - data_start;
	map_pages_to_vaddr((void *) data_start, (void *) (data_start - KERNEL_VIRTUAL_BASE),
		size, VM_WRITE | VM_NOEXEC);
	
	size = (uintptr_t) &_vdso_sect_end - vdso_start;
	map_pages_to_vaddr((void *) vdso_start, (void *) (vdso_start - KERNEL_VIRTUAL_BASE),
		size, VM_WRITE);

	__asm__ __volatile__("movq %0, %%cr3"::"r"(pml));

	kernel_address_space.cr3 = pml;
}

void paging_invalidate(void *page, size_t pages)
{
	uintptr_t p = (uintptr_t) page;

	for(size_t i = 0; i < pages; i++, p += 4096)
	{
		__native_tlb_invalidate_page((void *) p);
	}
}

void *vm_map_page(struct process *proc, uint64_t virt, uint64_t phys, uint64_t prot)
{
	PML4 *pml = proc ? proc->address_space.cr3 : get_current_pml4();
	
	assert(pml != NULL);

	return paging_map_phys_to_virt(pml, virt, phys, prot);
}

void paging_free_pml2(PML2 *pml)
{
	for(int i = 0; i < 512; i++)
	{
		if(pml->entries[i] & X86_PAGING_PRESENT && !(pml->entries[i] & X86_PAGING_HUGE))
		{
			/* We don't need to free pages since these functions
			 * are supposed to only tear down paging tables */
			unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);

			free_page(phys_to_page(phys_addr));
		}
	}
}

void paging_free_pml3(PML3 *pml)
{
	for(int i = 0; i < 512; i++)
	{
		if(pml->entries[i] & X86_PAGING_PRESENT)
		{
			unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);
			PML2 *pml2 = PHYS_TO_VIRT(phys_addr);
			paging_free_pml2(pml2);

			free_page(phys_to_page(phys_addr));
		}
	}
}

void paging_free_page_tables(struct mm_address_space *mm)
{
	PML4 *pml = PHYS_TO_VIRT(mm->cr3);

	for(int i = 0; i < 256; i++)
	{
		if(pml->entries[i] & X86_PAGING_PRESENT)
		{
			unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);
			PML3 *pml3 = PHYS_TO_VIRT(phys_addr);
			paging_free_pml3(pml3);

			free_page(phys_to_page(phys_addr));
			pml->entries[i] = 0;
		}
	}

	free_page(phys_to_page(mm->cr3));
}