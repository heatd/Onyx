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
#define X86_PAGING_USER			(1 << 2)
#define X86_PAGING_WRITETHROUGH		(1 << 3)
#define X86_PAGING_PCD			(1 << 4)
#define X86_PAGING_ACCESSED		(1 << 5)
#define X86_PAGING_DIRTY		(1 << 6)
#define X86_PAGING_PAT			(1 << 7)
#define X86_PAGING_HUGE			(1 << 7)
#define X86_PAGING_GLOBAL		(1 << 8)
#define X86_PAGING_NX			(1UL << 63)

#define X86_PAGING_FLAGS_TO_SAVE_ON_MPROTECT		\
(X86_PAGING_GLOBAL | X86_PAGING_HUGE | X86_PAGING_USER | X86_PAGING_PRESENT | X86_PAGING_ACCESSED | \
X86_PAGING_DIRTY | X86_PAGING_WRITETHROUGH | X86_PAGING_PCD | X86_PAGING_PAT)

void* paging_map_phys_to_virt(PML *__pml, uint64_t virt, uint64_t phys, uint64_t prot);

static inline void __native_tlb_invalidate_page(void *addr)
{
	__asm__ __volatile__("invlpg (%0)" : : "b"(addr) : "memory");
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
	return p != NULL ? (void *) pfn_to_paddr(page_to_pfn(p)) : NULL;
}

PML *boot_pml4;

PML *get_current_pml4(void)
{
	struct process *p = get_current_process();
	if(!p)
		return boot_pml4;
	return (PML*) p->address_space.arch_mmu.cr3;
}

#define HUGE1GB_SHIFT		30
#define HUGE1GB_SIZE		0x40000000
#define LARGE2MB_SHIFT		21
#define LARGE2MB_SIZE		0x200000

void *__virtual2phys(PML *__pml, void *ptr)
{
	unsigned long virt = (unsigned long ) ptr;
	const unsigned int paging_levels = 4;
	unsigned int indices[paging_levels];
	
	for(unsigned int i = 0; i < paging_levels; i++)
	{
		indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
	}

	PML *pml = (PML*)((uint64_t) __pml + PHYS_BASE);
	
	for(unsigned int i = paging_levels; i != 1; i--)
	{
		uint64_t entry = pml->entries[indices[i - 1]];
		
		if(!(entry & X86_PAGING_PRESENT))
			return (void *) -1;
		
		if(entry & X86_PAGING_HUGE)
		{
			/* Is huge page, check if it's a 1gb or 2mb */
			/* 1GB pages reside in PML3, 2MB pages reside in PML2 */
			bool is_1gb = i == 3;
			unsigned long size = is_1gb ? HUGE1GB_SIZE : LARGE2MB_SIZE;
			unsigned long page_base = PML_EXTRACT_ADDRESS(entry);
			unsigned long page_off = virt & (size - 1);
			return (void *) (page_base + page_off);
		}


		pml = PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(entry));
	}

	unsigned long phys = PML_EXTRACT_ADDRESS(pml->entries[indices[0]]);
	unsigned long page_off = virt & (PAGE_SIZE - 1);

	return (void *) (phys + page_off);
}

void *virtual2phys(void *ptr)
{
	return __virtual2phys(get_current_pml4(), ptr);
}

extern PML pdptphysical_map;
static PML pdphysical_map __attribute__((aligned(PAGE_SIZE)));

static PML placement_mappings_page_dir __attribute__((aligned(4096)));
static PML placement_mappings_page_table __attribute__((aligned(4096)));

unsigned long placement_mappings_start = 0xffffffffffc00000;

#define EARLY_BOOT_GDB_DELAY	\
volatile int __gdb_debug_counter = 0; \
while(__gdb_debug_counter != 1)


void __native_tlb_invalidate_all(void)
{
	__asm__ __volatile__("mov %%cr3, %%rax\nmov %%rax, %%cr3":::"rax");
}

void *x86_placement_map(unsigned long _phys)
{
	if(_phys > placement_mappings_start)
		__asm__ __volatile__("ud2"); // HMMMMM, :thinking emoji:
	//printf("_phys: %lx\n", _phys);
	unsigned long phys = _phys & ~(PAGE_SIZE - 1);
	//printf("phys: %lx\n", phys);

	/* Map two pages so memory that spans both pages can get accessed */
	paging_map_phys_to_virt(get_current_pml4(), placement_mappings_start, phys, VM_WRITE);
	paging_map_phys_to_virt(get_current_pml4(), placement_mappings_start + PAGE_SIZE, phys + PAGE_SIZE,
						VM_WRITE);
	__native_tlb_invalidate_page((void *) placement_mappings_start);
	__native_tlb_invalidate_page((void *) (placement_mappings_start + PAGE_SIZE));
	return (void *) (placement_mappings_start + (_phys - phys));
}

void x86_setup_placement_mappings(void)
{
	const unsigned int paging_levels = 4;
	unsigned int indices[paging_levels];
	const unsigned long virt = placement_mappings_start;

	PML *pml = boot_pml4;

	for(unsigned int i = 0; i < paging_levels; i++)
	{
		indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
	}

	for(unsigned int i = paging_levels; i != 1; i--)
	{
		uint64_t entry = pml->entries[indices[i - 1]];
		if(entry & 1)
		{
			void *page = (void*) PML_EXTRACT_ADDRESS(entry);
			pml = (PML*) page;
		}
		else
		{
			unsigned long page = 0;
			if(i == 3)
			{
				page = ((unsigned long) &placement_mappings_page_dir - KERNEL_VIRTUAL_BASE);
			}
			else if(i == 2)
			{
				page = ((unsigned long) &placement_mappings_page_table - KERNEL_VIRTUAL_BASE);
			}
			else
			{
				/* We only handle non-present page tables for PML1 and 2 */
				__asm__ __volatile__("cli; hlt");
			}
		
			pml->entries[indices[i - 1]] = make_pml3e(page, 0, 0, 1, 0, 0, 0, 1, 1);

			pml = (PML *) page;
		}
	}
}

void paging_init(void)
{
	/* Get the current PML and store it */
	__asm__ __volatile__("movq %%cr3, %%rax\t\nmovq %%rax, %0":"=r"(boot_pml4));

	/* Bootstrap the first 1GB */
	uintptr_t virt = PHYS_BASE;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	uint64_t* entry = &boot_pml4->entries[decAddr.pml4];
	PML* pml3 = (PML*) &pdptphysical_map;
	
	*entry = make_pml4e((uint64_t) pml3, 0, 0, 0, 0, 1, 1);
	entry = &pml3->entries[decAddr.pdpt];
	*entry = make_pml3e(((uint64_t) &pdphysical_map - KERNEL_VIRTUAL_BASE), 0, 0, 1, 0, 0, 0, 1, 1);
	
	for(size_t j = 0; j < 512; j++)
	{
		uintptr_t p = j * 0x200000; 

		pdphysical_map.entries[j] = p | X86_PAGING_WRITE | X86_PAGING_PRESENT | X86_PAGING_GLOBAL |
		                            X86_PAGING_NX | X86_PAGING_HUGE;
	}

	x86_setup_placement_mappings();

}

void paging_map_all_phys(void)
{
	bool is_1gb_supported = x86_has_cap(X86_FEATURE_PDPE1GB);

	printf("Is 1gb supported? %s\n", is_1gb_supported ? "yes" : "no");
	uintptr_t virt = PHYS_BASE;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	uint64_t* entry = &get_current_pml4()->entries[decAddr.pml4];
	PML* pml3 = (PML*) &pdptphysical_map;

	*entry = make_pml4e((uint64_t) pml3, 0, 0, 0, 0, 1, 1);

	if(is_1gb_supported)
	{
		for(size_t i = 0; i < 512; i++)
		{
			entry = &pml3->entries[i];
			*entry = make_pml3e(i * 0x40000000, 1, 0, 1, 0, 0, 0, 1, 1);
			*entry |= X86_PAGING_HUGE;
		}
	}
	else
	{
		PML new_pml3;
		/* Use 2MiB pages instead */
		uint64_t *entry = &new_pml3.entries[0];
		for(size_t i = 0; i < 512; i++)
		{
			void *ptr = alloc_boot_page(1, 0);

			assert(ptr != NULL);

			*entry = make_pml3e(((unsigned long) ptr), 1, 0,
				1, 0, 0, 0, 1, 1);

			PML *pd = (PML*) x86_placement_map((unsigned long) ptr);

			for(size_t j = 0; j < 512; j++)
			{
				uintptr_t p = i * 512 * 0x200000 + j * 0x200000;

				pd->entries[j] = p | X86_PAGING_WRITE | X86_PAGING_PRESENT | X86_PAGING_GLOBAL |
		                            X86_PAGING_NX | X86_PAGING_HUGE;
			}

			entry++;
		}

		memcpy(pml3, &new_pml3, sizeof(PML));
	}

	for(size_t i = 0; i < 512; i++)
		__native_tlb_invalidate_page((void*)(virt + i * 0x40000000));
}

void* paging_map_phys_to_virt_large_early(uint64_t virt, uint64_t phys, uint64_t prot)
{
	bool user = 0;
	if (virt < 0x00007fffffffffff)
		user = 1;
	if(!get_current_pml4())
		return NULL;
	decomposed_addr_t decAddr;
	memcpy(&decAddr, &virt, sizeof(decomposed_addr_t));
	PML *pml4 = (PML*)((uint64_t)get_current_pml4() + KERNEL_VIRTUAL_BASE);
	
	uint64_t* entry = &pml4->entries[decAddr.pml4];
	PML* pml3 = NULL;
	PML* pml2 = NULL;
	/* If its present, use that pml3 */
	if(*entry & X86_PAGING_PRESENT) {
		pml3 = (PML*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else { /* Else create one */
		pml3 = (PML*) alloc_pt();
		if(!pml3)
			return NULL;
		printf("PML: %p\n", pml3);
		while(1);
		*entry = make_pml4e((uint64_t)pml3, 0, 0, 0, user ? 1 : 0, 1, 1);
	}
	pml3 = (PML*)((uint64_t)pml3 + KERNEL_VIRTUAL_BASE);
	entry = &pml3->entries[decAddr.pdpt];
	if(*entry & X86_PAGING_PRESENT) {
		pml2 = (PML*)(*entry & 0x0FFFFFFFFFFFF000);
	}
	else {
		pml2 = (PML*) alloc_pt();
		if(!pml2)
			return NULL;
		printf("PML: %p\n", pml2);
		while(1);
		*entry = make_pml3e( (uint64_t)pml2, 0, 0, 0, 0, 0, user ? 1 : 0, 1, 1);
	}
	pml2 = (PML*)((uint64_t)pml2 + KERNEL_VIRTUAL_BASE);
	entry = &pml2->entries[decAddr.pd];
	
	*entry = make_pml2e(phys, (prot & 4), 0,
		 (prot & 2) ? 1 : 0, 0, 0, (prot & 0x80) ? 1 : 0,
		 (prot & 1)? 1 : 0, 1);
	*entry |= X86_PAGING_HUGE;
	return (void*) virt;
} 

void* paging_map_phys_to_virt(PML *__pml, uint64_t virt, uint64_t phys, uint64_t prot)
{
	bool user = 0;
	if (virt < 0x00007fffffffffff)
		user = true;

	struct mm_address_space *as = NULL;
	if(!user)
		as = &kernel_address_space;
	else
		as = get_current_address_space();


	const unsigned int paging_levels = 4;
	unsigned int indices[paging_levels];

	/* Note: page table flags are different from page perms because a page table's
	 * permissions apply throughout the whole table.
	 * Because of that, the PT's flags are Present | Write | (possible User) 
	*/
	uint64_t page_table_flags = X86_PAGING_PRESENT | X86_PAGING_WRITE |
		(user ? X86_PAGING_USER : 0);
	
	for(unsigned int i = 0; i < paging_levels; i++)
	{
		indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
	}

	PML *pml = (PML*)((uint64_t) __pml + PHYS_BASE);
	
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
			if(!page)
				return NULL;
			pml->entries[indices[i - 1]] = (uint64_t) page | page_table_flags;
			pml = PHYS_TO_VIRT(page);
		}
	}
	
	bool noexec = prot & VM_NOEXEC ? true : false;
	bool global = prot & VM_USER ? false : true;
	user = prot & VM_USER ? true : false;
	bool write = prot & VM_WRITE ? true : false;
	unsigned int cache_type = vm_prot_to_cache_type(prot);
	uint8_t caching_bits = cache_to_paging_bits(cache_type);

	uint64_t page_prots = 	(noexec ? X86_PAGING_NX : 0) |
				(global ? X86_PAGING_GLOBAL : 0) |
				(user ? X86_PAGING_USER : 0) |
				(write ? X86_PAGING_WRITE : 0) |
				((caching_bits << 3) & 0x3) |
				X86_PAGING_PRESENT;

	if(prot & VM_DONT_MAP_OVER && pml->entries[indices[0]] & X86_PAGING_PRESENT)
		return (void *) virt;
	
	pml->entries[indices[0]] = phys | page_prots;

	increment_vm_stat(as, resident_set_size, PAGE_SIZE);

	return (void*) virt;
}

bool pml_is_empty(void *_pml)
{
	PML *pml = _pml;
	for(int i = 0; i < 512; i++)
	{
		if(pml->entries[i])
			return false;
	}
	return true;
}

void *paging_unmap(void* memory)
{
	bool user = 0;
	if ((unsigned long) memory < 0x00007fffffffffff)
		user = true;

	struct mm_address_space *as = NULL;
	if(!user)
		as = &kernel_address_space;
	else
		as = get_current_address_space();

	decomposed_addr_t dec;
	memcpy(&dec, &memory, sizeof(decomposed_addr_t));
	PML *pml4 = (PML*)((uint64_t) get_current_pml4() + PHYS_BASE);
	
	uint64_t* entry = &pml4->entries[dec.pml4];

	if(!(*entry & X86_PAGING_PRESENT))
		return NULL;
	PML *pml3 = (PML*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml3->entries[dec.pdpt];
	if(!(*entry & X86_PAGING_PRESENT)) /* If the entry isn't committed, just return */
		return NULL;
	PML *pml2 = (PML*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml2->entries[dec.pd];

	if(!(*entry & X86_PAGING_PRESENT)) /* If the entry isn't committed, just return */
		return NULL;
	PML *pml1 = (PML*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml1->entries[dec.pt];

	if(!(*entry & X86_PAGING_PRESENT)) /* If the entry isn't committed, just return */
		return NULL;

	uintptr_t address = PML_EXTRACT_ADDRESS(*entry);
	*entry = 0;

	/* Now that we've freed the destination page, work our way upwards to check if the paging structures are empty 
	   If so, free them as well 
	*/
	if(pml_is_empty(pml1))
	{
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

	decrement_vm_stat(as, resident_set_size, PAGE_SIZE);

	return (void*) address;
}

int paging_clone_as(struct mm_address_space *addr_space)
{
	PML *new_pml = alloc_pt();
	if(!new_pml)
		return -1;
	PML *p = PHYS_TO_VIRT(new_pml);
	PML *curr = (PML*)((uint64_t) get_current_pml4() + PHYS_BASE);
	/* Copy the upper 256 entries of the PML in order to map
	 * the kernel in the process's address space
	*/

	memcpy(&p->entries[256], &curr->entries[256], 256 * sizeof(uint64_t));

	addr_space->arch_mmu.cr3 = new_pml;
	return 0;
}

PML *paging_fork_pml(PML *pml, int entry)
{
	uint64_t old_address = PML_EXTRACT_ADDRESS(pml->entries[entry]);
	uint64_t perms = pml->entries[entry] & 0xF000000000000FFF;

	void *new_pt = alloc_pt();
	if(!new_pt)
		return NULL;

	pml->entries[entry] = (uint64_t) new_pt | perms;
	PML *new_pml = (PML*) PHYS_TO_VIRT(new_pt);
	PML *old_pml = PHYS_TO_VIRT(old_address);
	memcpy(new_pml, old_pml, sizeof(PML));
	return new_pml;
}

int paging_fork_tables(struct mm_address_space *addr_space)
{
	struct page *page = alloc_page(0);
	if(!page)
		return -1;
	unsigned long new_pml = pfn_to_paddr(page_to_pfn(page));
	PML *p = PHYS_TO_VIRT(new_pml);
	PML *curr = PHYS_TO_VIRT(get_current_pml4());
	memcpy(p, curr, sizeof(PML));

	PML *mod_pml = PHYS_TO_VIRT(new_pml);
	/* TODO: Destroy the page tables on failure */
	for(int i = 0; i < 256; i++)
	{
		if(mod_pml->entries[i] & X86_PAGING_PRESENT)
		{
			PML *pml3 = (PML*) paging_fork_pml(mod_pml, i);
			if(!pml3)
			{
				return -1;
			}

			for(int j = 0; j < PAGE_TABLE_ENTRIES; j++)
			{
				if(pml3->entries[j] & X86_PAGING_PRESENT)
				{
					PML *pml2 = (PML*) paging_fork_pml((PML*) pml3, j);
					if(!pml2)
					{
						return -1;
					}

					for(int k = 0; k < PAGE_TABLE_ENTRIES; k++)
					{
						if(pml2->entries[k] & X86_PAGING_PRESENT && !(pml2->entries[k] & (1<<7)))
						{
							PML *pml1 = (PML*) paging_fork_pml((PML*)pml2, k);
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
	
	addr_space->arch_mmu.cr3 = (void *) new_pml;
	return 0;
}

void paging_load_cr3(PML *pml)
{
	assert(pml != NULL);
	PML *oldpml;
	__asm__ __volatile__("movq %%cr3, %%rax\t\nmovq %%rax, %0":"=r"(oldpml));
	if(oldpml == pml)
		return;
	__asm__ __volatile__("movq %0, %%cr3"::"r"(pml));
}

bool x86_get_pt_entry(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm)
{
	unsigned long virt = (unsigned long) addr;
	const unsigned int paging_levels = 4;
	unsigned int indices[paging_levels];

	for(unsigned int i = 0; i < paging_levels; i++)
	{
		indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
	}

	PML *pml = (PML*)((unsigned long) mm->arch_mmu.cr3 + PHYS_BASE);
	
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
			return false;
		}
	}

	*entry_ptr = &pml->entries[indices[0]];

	return true;
}

bool __paging_change_perms(struct mm_address_space *mm, void *addr, int prot)
{
	uint64_t *entry;
	if(!x86_get_pt_entry(addr, &entry, mm))
	{
		return false;
	}

	uint64_t pt_entry = *entry;
	uint64_t perms = pt_entry & X86_PAGING_FLAGS_TO_SAVE_ON_MPROTECT;
	uint64_t page = PML_EXTRACT_ADDRESS(pt_entry);

	if(prot & VM_NOEXEC)
		perms |= X86_PAGING_NX;
	if(prot & VM_WRITE)
		perms |= X86_PAGING_WRITE;
	*entry = perms | page;

	return true;
}

bool paging_change_perms(void *addr, int prot)
{
	struct mm_address_space *as = &kernel_address_space;
	if((unsigned long) addr < VM_HIGHER_HALF)
		as = get_current_address_space();
	
	return __paging_change_perms(as, addr, prot);
}

bool paging_write_protect(void *addr, struct mm_address_space *mm)
{
	uint64_t *ptentry;
	if(!x86_get_pt_entry(addr, &ptentry, mm))
		return false;

	*ptentry = *ptentry & ~X86_PAGING_WRITE;

	return true;
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
	PML *pml4 = (PML*)((uint64_t)get_current_pml4() + PHYS_BASE);
	
	uint64_t* entry = &pml4->entries[dec.pml4];
	if(*entry == 0)
	{
		printk("isn't mapped(PML %p)\n", pml4);
		return;
	}
	PML *pml3 = (PML*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml3->entries[dec.pdpt];
	if(*entry == 0)
	{
		printk("isn't mapped(PML %p)\n", pml3);
		return;
	}
	PML *pml2 = (PML*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml2->entries[dec.pd];
	if(*entry == 0)
	{
		printk("isn't mapped(PML %p)\n", pml2);
		return;
	}
	PML *pml1 = (PML*)((*entry & 0x0FFFFFFFFFFFF000) + PHYS_BASE);
	entry = &pml1->entries[dec.pt];
	if(*entry == 0)
	{
		printk("isn't mapped(PML %p)\n", pml1);
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
	PML *original_pml = boot_pml4;
	PML *pml = alloc_pt();
	assert(pml != NULL);
	boot_pml4 = pml;

	uintptr_t text_start = (uintptr_t) &_text_start;
	uintptr_t data_start = (uintptr_t) &_data_start;
	uintptr_t vdso_start = (uintptr_t) &_vdso_sect_start;

	memcpy((PML*)((uintptr_t) pml + PHYS_BASE), (PML*)((uintptr_t) original_pml + PHYS_BASE),
		sizeof(PML));
	PML *p = (PML*)((uintptr_t) pml + PHYS_BASE);
	p->entries[511] = 0UL;
	p->entries[0] = 0UL;

	size_t size = (uintptr_t) &_text_end - text_start;
	map_pages_to_vaddr((void *) text_start, (void *) (text_start - KERNEL_VIRTUAL_BASE),
		size, 0);

	size = (uintptr_t) &_data_end - data_start;
	map_pages_to_vaddr((void *) data_start, (void *) (data_start - KERNEL_VIRTUAL_BASE),
		size, VM_WRITE | VM_NOEXEC);
	
	size = (uintptr_t) &_vdso_sect_end - vdso_start;
	map_pages_to_vaddr((void *) vdso_start, (void *) (vdso_start - KERNEL_VIRTUAL_BASE),
		size, VM_WRITE);

	percpu_map_master_copy();

	__asm__ __volatile__("movq %0, %%cr3"::"r"(pml));

	kernel_address_space.arch_mmu.cr3 = pml;
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
	PML *pml = proc ? proc->address_space.arch_mmu.cr3 : get_current_pml4();
	
	assert(pml != NULL);

	return paging_map_phys_to_virt(pml, virt, phys, prot);
}

void paging_free_pml2(PML *pml)
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

void paging_free_pml3(PML *pml)
{
	for(int i = 0; i < 512; i++)
	{
		if(pml->entries[i] & X86_PAGING_PRESENT)
		{
			unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);
			PML *pml2 = PHYS_TO_VIRT(phys_addr);
			paging_free_pml2(pml2);

			free_page(phys_to_page(phys_addr));
		}
	}
}

void paging_free_page_tables(struct mm_address_space *mm)
{
	PML *pml = PHYS_TO_VIRT(mm->arch_mmu.cr3);

	for(int i = 0; i < 256; i++)
	{
		if(pml->entries[i] & X86_PAGING_PRESENT)
		{
			unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);
			PML *pml3 = PHYS_TO_VIRT(phys_addr);
			paging_free_pml3(pml3);

			free_page(phys_to_page(phys_addr));
			pml->entries[i] = 0;
		}
	}

	free_page(phys_to_page((unsigned long) mm->arch_mmu.cr3));
}

unsigned long get_mapping_info(void *addr)
{
	struct mm_address_space *as = &kernel_address_space;
	if((unsigned long) addr < VM_HIGHER_HALF)
		as = get_current_address_space();
	
	return __get_mapping_info(addr, as);
}

unsigned long __get_mapping_info(void *addr, struct mm_address_space *as)
{
	const unsigned long virt = (unsigned long) addr; 
	const unsigned int paging_levels = 4;
	unsigned int indices[paging_levels];

	for(unsigned int i = 0; i < paging_levels; i++)
	{
		indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
	}

	PML *pml = (PML*)((unsigned long) as->arch_mmu.cr3 + PHYS_BASE);
	
	for(unsigned int i = paging_levels; i != 1; i--)
	{
		unsigned long entry = pml->entries[indices[i - 1]];
		if(entry & X86_PAGING_PRESENT)
		{
			void *page = (void*) PML_EXTRACT_ADDRESS(entry);
			pml = PHYS_TO_VIRT(page);
		}
		else
		{
			return PAGE_NOT_PRESENT;
		}
	}

	unsigned long pt_entry = pml->entries[indices[0]];

	unsigned long ret = 0;

	if(pt_entry & X86_PAGING_PRESENT)
		ret |= PAGE_PRESENT;
	else
	{
		return PAGE_NOT_PRESENT;
	}

	if(pt_entry & X86_PAGING_USER)
		ret |= PAGE_USER;
	if(pt_entry & X86_PAGING_WRITE)
		ret |= PAGE_WRITABLE;
	if(!(pt_entry & X86_PAGING_NX))
		ret |= PAGE_EXECUTABLE;
	if(pt_entry & X86_PAGING_DIRTY)
		ret |= PAGE_DIRTY;
	if(pt_entry & X86_PAGING_ACCESSED)
		ret |= PAGE_ACCESSED;
	if(pt_entry & X86_PAGING_GLOBAL)
		ret |= PAGE_GLOBAL;

	ret |= PML_EXTRACT_ADDRESS(pt_entry);

	return ret;
}

void vm_free_arch_mmu(struct arch_mm_address_space *mm)
{
	free_page(phys_to_page((unsigned long) mm->cr3));
}

void vm_load_arch_mmu(struct arch_mm_address_space *mm)
{
	paging_load_cr3(mm->cr3);
}

void vm_save_current_mmu(struct mm_address_space *mm)
{
	mm->arch_mmu.cr3 = get_current_pml4();
}
