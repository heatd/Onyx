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
#include <onyx/smp.h>

static const unsigned int x86_paging_levels = 4;
static const unsigned int x86_max_paging_levels = 5;

#define X86_CACHING_BITS(index) ((((index) & 0x3) << 3) | (((index >> 2) & 1) << 7))

#define PML_EXTRACT_ADDRESS(n)  ((n) & 0x0FFFFFFFFFFFF000)
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

#define X86_PAGING_PROT_BITS   ((PAGE_SIZE - 1) | X86_PAGING_NX)

#define X86_PAGING_FLAGS_TO_SAVE_ON_MPROTECT		\
(X86_PAGING_GLOBAL | X86_PAGING_HUGE | X86_PAGING_USER | X86_PAGING_ACCESSED | \
X86_PAGING_DIRTY | X86_PAGING_WRITETHROUGH | X86_PAGING_PCD | X86_PAGING_PAT)

void* paging_map_phys_to_virt(struct mm_address_space *as, uint64_t virt, uint64_t phys, uint64_t prot);

static inline void __native_tlb_invalidate_page(void *addr)
{
	__asm__ __volatile__("invlpg (%0)" : : "b"(addr) : "memory");
}

bool x86_get_pt_entry(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm);

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

typedef struct 
{
	uint64_t offsetFromPage : 12;
	uint64_t pt : 9;
	uint64_t pd : 9;
	uint64_t pdpt : 9;
	uint64_t pml4 : 9;
	uint64_t rest : 16;
} decomposed_addr_t;

unsigned long allocated_page_tables = 0;

PML *alloc_pt(void)
{
	struct page *p = alloc_page(0);
	if(p)
	{
		__atomic_add_fetch(&allocated_page_tables, 1, __ATOMIC_RELAXED);
	}

	return p != nullptr ? (PML *) pfn_to_paddr(page_to_pfn(p)) : nullptr;
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

static void x86_addr_to_indices(unsigned long virt, unsigned int *indices)
{
	for(unsigned int i = 0; i < x86_paging_levels; i++)
	{
		indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
	}
}

void *__virtual2phys(PML *__pml, void *ptr)
{
	unsigned long virt = (unsigned long ) ptr;
	unsigned int indices[x86_max_paging_levels];
	
	x86_addr_to_indices(virt, indices);

	PML *pml = (PML*)((uint64_t) __pml + PHYS_BASE);
	
	for(unsigned int i = x86_paging_levels; i != 1; i--)
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


		pml = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(entry));
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

extern "C"
void __native_tlb_invalidate_all(void)
{
	__asm__ __volatile__("mov %%cr3, %%rax\nmov %%rax, %%cr3":::"rax", "memory");
}

void *x86_placement_map(unsigned long _phys)
{
	if(_phys > placement_mappings_start)
		__asm__ __volatile__("ud2"); // HMMMMM, :thinking emoji:
	//printf("_phys: %lx\n", _phys);
	unsigned long phys = _phys & ~(PAGE_SIZE - 1);
	//printf("phys: %lx\n", phys);

	/* I'm not sure that kernel_address_space has been initialised yet, so we'll fill this with the cr3 */
	kernel_address_space.arch_mmu.cr3 = get_current_pml4();

	/* Map two pages so memory that spans both pages can get accessed */
	paging_map_phys_to_virt(&kernel_address_space, placement_mappings_start, phys, VM_WRITE);
	paging_map_phys_to_virt(&kernel_address_space, placement_mappings_start + PAGE_SIZE, phys + PAGE_SIZE,
						VM_WRITE);
	__native_tlb_invalidate_page((void *) placement_mappings_start);
	__native_tlb_invalidate_page((void *) (placement_mappings_start + PAGE_SIZE));
	return (void *) (placement_mappings_start + (_phys - phys));
}

void x86_setup_placement_mappings(void)
{
	unsigned int indices[x86_max_paging_levels];
	const unsigned long virt = placement_mappings_start;

	PML *pml = boot_pml4;

	x86_addr_to_indices(virt, indices);

	for(unsigned int i = x86_paging_levels; i != 1; i--)
	{
		uint64_t entry = pml->entries[indices[i - 1]];
		if(entry & X86_PAGING_PRESENT)
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
		entry = &new_pml3.entries[0];
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

void* paging_map_phys_to_virt(struct mm_address_space *as, uint64_t virt, uint64_t phys, uint64_t prot)
{
	bool user = 0;
	if (virt < 0x00007fffffffffff)
		user = true;
	
	if(!as && user)
	{
		as = get_current_address_space();
	}
	else if(!user)
		as = &kernel_address_space;

	unsigned int indices[x86_max_paging_levels];

	/* Note: page table flags are different from page perms because a page table's
	 * permissions apply throughout the whole table.
	 * Because of that, the PT's flags are Present | Write | (possible User) 
	*/
	uint64_t page_table_flags = X86_PAGING_PRESENT | X86_PAGING_WRITE |
		(user ? X86_PAGING_USER : 0);
	
	x86_addr_to_indices(virt, indices);

	PML *pml = (PML*)((uint64_t) as->arch_mmu.cr3 + PHYS_BASE);
	
	for(unsigned int i = x86_paging_levels; i != 1; i--)
	{
		uint64_t entry = pml->entries[indices[i - 1]];
		if(entry & X86_PAGING_PRESENT)
		{
			void *page = (void*) PML_EXTRACT_ADDRESS(entry);
			pml = (PML *) PHYS_TO_VIRT(page);
		}
		else
		{
			assert(entry == 0);
			void *page = alloc_pt();
			if(!page)
				return NULL;
			
			increment_vm_stat(as, page_tables_size, PAGE_SIZE);
			pml->entries[indices[i - 1]] = (uint64_t) page | page_table_flags;
			pml = (PML *) PHYS_TO_VIRT(page);
		}
	}
	
	bool noexec = prot & VM_NOEXEC ? true : false;
	bool global = prot & VM_USER ? false : true;
	user = prot & VM_USER ? true : false;
	bool write = prot & VM_WRITE ? true : false;
	bool readable = prot & (VM_READ | VM_WRITE) || !noexec;
	unsigned int cache_type = vm_prot_to_cache_type(prot);
	uint8_t caching_bits = cache_to_paging_bits(cache_type);

	uint64_t page_prots = (noexec ? X86_PAGING_NX : 0) |
				(global ? X86_PAGING_GLOBAL : 0) |
				(user ? X86_PAGING_USER : 0) |
				(write ? X86_PAGING_WRITE : 0) |
				X86_CACHING_BITS(caching_bits) |
				(readable ? X86_PAGING_PRESENT : 0);

	if(prot & VM_DONT_MAP_OVER && pml->entries[indices[0]] & X86_PAGING_PRESENT)
		return (void *) virt;
	
	uint64_t old = pml->entries[indices[0]];
	
	pml->entries[indices[0]] = phys | page_prots;

	if(old == 0)
	{
		increment_vm_stat(as, resident_set_size, PAGE_SIZE);
	}

	return (void*) virt;
}

bool pml_is_empty(const PML *pml)
{
	for(int i = 0; i < 512; i++)
	{
		if(pml->entries[i])
			return false;
	}

	return true;
}

struct pt_location
{
	PML *table;
	unsigned int index;
};

bool x86_get_pt_entry_with_ptables(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm,
                                   struct pt_location location[4])
{
	unsigned long virt = (unsigned long) addr;
	unsigned int indices[x86_max_paging_levels];

	for(unsigned int i = 0; i < x86_paging_levels; i++)
	{
		indices[i] = (virt >> 12) >> (i * 9) & 0x1ff;
		location[4 - 1 - i].index = indices[i];
	}

	PML *pml = (PML*)((unsigned long) mm->arch_mmu.cr3 + PHYS_BASE);
	unsigned int location_index = 0;
	
	for(unsigned int i = x86_paging_levels; i != 1; i--)
	{
		uint64_t entry = pml->entries[indices[i - 1]];
		location[location_index].table = pml;
		location[location_index++].index = indices[i - 1];

		if(entry & X86_PAGING_PRESENT)
		{
			void *page = (void*) PML_EXTRACT_ADDRESS(entry);
			pml = (PML *) PHYS_TO_VIRT(page);
		}
		else
		{
			return false;
		}
	}

	location[location_index].table = pml;
	location[location_index++].index = indices[0];

	*entry_ptr = &pml->entries[indices[0]];

	return true;
}

int paging_clone_as(struct mm_address_space *addr_space)
{
	PML *new_pml = alloc_pt();
	if(!new_pml)
		return -1;
	
	addr_space->page_tables_size = PAGE_SIZE;

	PML *p = (PML *) PHYS_TO_VIRT(new_pml);
	PML *curr = (PML*)((uint64_t) get_current_pml4() + PHYS_BASE);
	/* Copy the upper 256 entries of the PML in order to map
	 * the kernel in the process's address space
	*/

	memcpy(&p->entries[256], &curr->entries[256], 256 * sizeof(uint64_t));

	addr_space->arch_mmu.cr3 = new_pml;
	return 0;
}

PML *paging_fork_pml(PML *pml, int entry, struct mm_address_space *as)
{
	uint64_t old_address = PML_EXTRACT_ADDRESS(pml->entries[entry]);
	uint64_t perms = pml->entries[entry] & 0xF000000000000FFF;

	void *new_pt = alloc_pt();
	if(!new_pt)
		return NULL;

	increment_vm_stat(as, page_tables_size, PAGE_SIZE);

	pml->entries[entry] = (uint64_t) new_pt | perms;
	PML *new_pml = (PML*) PHYS_TO_VIRT(new_pt);
	PML *old_pml = (PML *) PHYS_TO_VIRT(old_address);
	memcpy(new_pml, old_pml, sizeof(PML));
	return new_pml;
}

int paging_fork_tables(struct mm_address_space *addr_space)
{
	struct page *page = alloc_page(0);
	if(!page)
		return -1;
	
	__atomic_add_fetch(&allocated_page_tables, 1, __ATOMIC_RELAXED);
	increment_vm_stat(addr_space, page_tables_size, PAGE_SIZE);

	unsigned long new_pml = pfn_to_paddr(page_to_pfn(page));
	PML *p = (PML *) PHYS_TO_VIRT(new_pml);
	PML *curr = (PML *) PHYS_TO_VIRT(get_current_pml4());
	memcpy(p, curr, sizeof(PML));

	PML *mod_pml = (PML *) PHYS_TO_VIRT(new_pml);
	/* TODO: Destroy the page tables on failure */
	for(int i = 0; i < 256; i++)
	{
		if(mod_pml->entries[i] & X86_PAGING_PRESENT)
		{
			PML *pml3 = (PML*) paging_fork_pml(mod_pml, i, addr_space);
			if(!pml3)
			{
				return -1;
			}

			for(int j = 0; j < PAGE_TABLE_ENTRIES; j++)
			{
				if(pml3->entries[j] & X86_PAGING_PRESENT)
				{
					PML *pml2 = (PML*) paging_fork_pml((PML*) pml3, j, addr_space);
					if(!pml2)
					{
						return -1;
					}

					for(int k = 0; k < PAGE_TABLE_ENTRIES; k++)
					{
						if(pml2->entries[k] & X86_PAGING_PRESENT &&
						   !(pml2->entries[k] & X86_PAGING_HUGE))
						{
							PML *pml1 = (PML*) paging_fork_pml((PML*)pml2, k, addr_space);
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

	__asm__ __volatile__("movq %%cr3, %0" : "=r"(oldpml));
	if(oldpml == pml)
		return;
	__asm__ __volatile__("movq %0, %%cr3"::"r"(pml));
}

bool x86_get_pt_entry(void *addr, uint64_t **entry_ptr, struct mm_address_space *mm)
{
	unsigned long virt = (unsigned long) addr;
	unsigned int indices[x86_max_paging_levels];

	x86_addr_to_indices(virt, indices);

	PML *pml = (PML*)((unsigned long) mm->arch_mmu.cr3 + PHYS_BASE);
	
	for(unsigned int i = x86_paging_levels; i != 1; i--)
	{
		uint64_t entry = pml->entries[indices[i - 1]];
		if(entry & X86_PAGING_PRESENT)
		{
			void *page = (void*) PML_EXTRACT_ADDRESS(entry);
			pml = (PML *) PHYS_TO_VIRT(page);
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
	MUST_HOLD_MUTEX(&mm->vm_lock);

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
	if(prot & VM_READ)
		perms |= X86_PAGING_PRESENT;
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

	kernel_address_space.arch_mmu.cr3 = pml;

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
}

unsigned long total_shootdowns = 0;

void paging_invalidate(void *page, size_t pages)
{
	uintptr_t p = (uintptr_t) page;

	for(size_t i = 0; i < pages; i++, p += PAGE_SIZE)
	{
		total_shootdowns++;
		__native_tlb_invalidate_page((void *) p);
	}
}

void *vm_map_page(struct mm_address_space *as, uint64_t virt, uint64_t phys, uint64_t prot)
{
	return paging_map_phys_to_virt(as, virt, phys, prot);
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
			PML *pml2 = (PML *) PHYS_TO_VIRT(phys_addr);
			paging_free_pml2(pml2);

			free_page(phys_to_page(phys_addr));
		}
	}
}

void paging_free_page_tables(struct mm_address_space *mm)
{
	PML *pml = (PML *) PHYS_TO_VIRT(mm->arch_mmu.cr3);

	for(int i = 0; i < 256; i++)
	{
		if(pml->entries[i] & X86_PAGING_PRESENT)
		{
			unsigned long phys_addr = PML_EXTRACT_ADDRESS(pml->entries[i]);
			PML *pml3 = (PML *) PHYS_TO_VIRT(phys_addr);
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
	unsigned int indices[x86_max_paging_levels];

	x86_addr_to_indices(virt, indices);

	PML *pml = (PML*)((unsigned long) as->arch_mmu.cr3 + PHYS_BASE);
	for(unsigned int i = x86_paging_levels; i != 1; i--)
	{
		unsigned long entry = pml->entries[indices[i - 1]];
		if(entry & X86_PAGING_PRESENT)
		{
			void *page = (void*) PML_EXTRACT_ADDRESS(entry);
			pml = (PML *) PHYS_TO_VIRT(page);
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
	paging_load_cr3((PML *) mm->cr3);
}

void vm_save_current_mmu(struct mm_address_space *mm)
{
	mm->arch_mmu.cr3 = get_current_pml4();
}

void vm_mmu_mprotect_page(struct mm_address_space *as, void *addr, int old_prots, int new_prots)
{
	uint64_t *ptentry;
	if(!x86_get_pt_entry(addr, &ptentry, as))
		return;
	
	if(!*ptentry)
		return;

	/* Make sure we don't accidentally mark a page as writable when 
	 * it's write-protected and we're changing some other bits.
	 * For example: mprotect(PROT_EXEC) on a COW'd supposedly writable
	 * page would try to re-apply the writable permission.
	 */

	/* In this function, we use the old_prots parameter to know whether it was a write-protected
	 * page.
	 */
	bool is_wp_page = !(*ptentry & X86_PAGING_WRITE) && old_prots & VM_WRITE;

	if(is_wp_page)
	{
		new_prots &= ~VM_WRITE;
		//printk("NOT VM_WRITING\n");
	}

	//printk("new prots: %x\n", new_prots);

	unsigned long paddr = PML_EXTRACT_ADDRESS(*ptentry);
	bool noexec = new_prots & VM_NOEXEC ? true : false;
	bool global = new_prots & VM_USER ? false : true;
	bool user = new_prots & VM_USER ? true : false;
	bool write = new_prots & VM_WRITE ? true : false;
	bool readable = new_prots & (VM_READ | VM_WRITE) || !noexec;

	unsigned int cache_type = vm_prot_to_cache_type(new_prots);
	uint8_t caching_bits = cache_to_paging_bits(cache_type);

	uint64_t page_prots = (noexec ? X86_PAGING_NX : 0) |
				(global ? X86_PAGING_GLOBAL : 0) |
				(user ? X86_PAGING_USER : 0) |
				(write ? X86_PAGING_WRITE : 0) |
				X86_CACHING_BITS(caching_bits) |
				(readable ? X86_PAGING_PRESENT : 0);
	*ptentry = paddr | page_prots;
}

class page_table_iterator
{
private:
	unsigned long curr_addr_;
	size_t length_;

public:

	struct mm_address_space *as_;

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
	bool debug;
#endif


	page_table_iterator(unsigned long virt, size_t len, struct mm_address_space *as) :
	      curr_addr_{virt}, length_{len}, as_{as}

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
	, debug{false}
#endif

	{
	}

	size_t length() const
	{
		return length_;
	}

	unsigned long curr_addr() const
	{
		return curr_addr_;
	}

	void adjust_length(size_t size)
	{
		if(size > length_)
		{
			length_ = 0;
			curr_addr_ += length_;
		}
		else
		{
			length_ -= size;
			curr_addr_ += size;
		}
	}
};

struct tlb_invalidation_tracker
{
	unsigned long virt_start;
	unsigned long virt_end;
	bool is_started, is_flushed;

	explicit tlb_invalidation_tracker() : virt_start{}, virt_end{}, is_started{}, is_flushed{}
	{}

	void invalidate_tracker()
	{
		virt_start = 0xDEADDAD;
		virt_end = 0xB0;
		is_started = false;
		is_flushed = false;
	}

	void flush()
	{
		if(!is_started)
			return;

		vm_invalidate_range(virt_start, (virt_end - virt_start) >> PAGE_SHIFT);
		invalidate_tracker();
	}

	constexpr void init(unsigned long vaddr, size_t size)
	{
		is_started = true;
		virt_start = vaddr;
		virt_end = vaddr + size;
		is_flushed = false;
	}

	void add_page(unsigned long vaddr, size_t size)
	{
		/* If we've already started on a run of pages and this one is contiguous, just set the tail */	
		if(is_started && virt_end == vaddr)
		{
			virt_end = vaddr + size;
		}
		else
		{
			/* Else, try flushing if is_started == true and restart the page run */
			flush();
			init(vaddr, size);
		}
	}

	~tlb_invalidation_tracker()
	{
		if(is_started && !is_flushed)
			flush();
	}
};

enum x86_page_table_levels : unsigned int
{
	PT_LEVEL,
	PD_LEVEL,
	PDPT_LEVEL,
	PML4_LEVEL,
	PML5_LEVEL
};

bool x86_is_pml5_enabled()
{
	return x86_paging_levels == 5;
}

static bool is_huge_page_level(unsigned int pt_level)
{
	constexpr unsigned int pdpt_level = PDPT_LEVEL, pd_level = PD_LEVEL;

	return pt_level == pdpt_level || pt_level == pd_level;
}

constexpr unsigned int level_to_entry_shift(unsigned int level)
{
	return (level * 9 + PAGE_SHIFT);
}

constexpr unsigned long level_to_entry_size(unsigned int level)
{
	return 1UL << level_to_entry_shift(level);
}

constexpr unsigned int addr_get_index(unsigned long virt, unsigned int pt_level)
{
	return (virt >> 12) >> (pt_level * 9) & 0x1ff;
}

#define MMU_UNMAP_CAN_FREE_PML    1
#define MMU_UNMAP_OK              0


static int x86_mmu_unmap(PML *table, unsigned int pt_level, page_table_iterator& it)
{
	unsigned int index = addr_get_index(it.curr_addr(), pt_level);

	/* Get the size that each entry represents here */
	auto entry_size = level_to_entry_size(pt_level);

	tlb_invalidation_tracker invd_tracker;
	unsigned int i;

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
	if(it.debug)
	{
		printk("level %u - index %x\n", pt_level, index);
	}
#endif

	for(i = index; i < PAGE_TABLE_ENTRIES && it.length(); i++)
	{
		auto &pt_entry = table->entries[i];

		if(!(pt_entry & X86_PAGING_PRESENT))
		{

#ifdef CONFIG_X86_MMU_UNMAP_DEBUG
			if(it.debug)
				printk("not present @ level %u\nentry size %lu\nlength %lu\n", pt_level, entry_size, it.length());
#endif
			auto to_skip = entry_size - (it.curr_addr() & (entry_size-1));

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
			if(it.debug)
			{
				printk("[level %u]: Skipping from %lx to %lx\n", pt_level, it.curr_addr(), it.curr_addr() + to_skip);
			}
#endif

			it.adjust_length(to_skip);
			continue;
		}

		bool is_huge_page = is_huge_page_level(pt_level) && pt_entry & X86_PAGING_HUGE;

		if(pt_level == PT_LEVEL || is_huge_page)
		{
			/* TODO: Handle huge page splitting */

#ifdef CONFIG_PT_ITERATOR_HAVE_DEBUG
			if(it.debug)
				printk("Unmapping %lx\n", it.curr_addr());
#endif

			unsigned long val = 0;
			__atomic_exchange(&pt_entry, &val, &val, __ATOMIC_RELEASE);

			if(val & X86_PAGING_ACCESSED)
			{
				invd_tracker.add_page(it.curr_addr(), entry_size);
			}

			it.adjust_length(entry_size);
			decrement_vm_stat(it.as_, resident_set_size, PAGE_SIZE);
		}
		else
		{
			PML *next_table = (PML *) PHYS_TO_VIRT(PML_EXTRACT_ADDRESS(pt_entry));
			int st = x86_mmu_unmap(next_table, pt_level - 1, it);

			if(st == MMU_UNMAP_CAN_FREE_PML)
			{
				auto page = phys_to_page(PML_EXTRACT_ADDRESS(pt_entry));

				pt_entry = 0;

				COMPILER_BARRIER();

				free_page(page);
				__atomic_sub_fetch(&allocated_page_tables, 1, __ATOMIC_RELAXED);
				decrement_vm_stat(it.as_, page_tables_size, PAGE_SIZE);
			}
		}
	}

	/* We can know that the table is 100% empty if we ran through the table */
	bool unmapped_whole_table = index == 0 && i == PAGE_TABLE_ENTRIES;

	/* Don't bother to free the PML or even check if it's empty if we're the top paging structure */
	if(pt_level != x86_paging_levels - 1 && (unmapped_whole_table || pml_is_empty(table)))
	{
		return MMU_UNMAP_CAN_FREE_PML;
	}

#if 0
	printk("nr entries %lu\n", nr_entries);

	printk("unmapping %lu\n", it.length());
#endif

	return MMU_UNMAP_OK;
}

int vm_mmu_unmap(struct mm_address_space *as, void *addr, size_t pages)
{
	unsigned long virt = (unsigned long) addr;
	size_t size = pages << PAGE_SHIFT;

	page_table_iterator it{virt, size, as};

	PML *first_level = (PML*) PHYS_TO_VIRT(as->arch_mmu.cr3);

	x86_mmu_unmap(first_level, x86_paging_levels - 1, it);

	assert(it.length() == 0);

	return 0;
}

static inline bool is_higher_half(unsigned long address)
{
	return address > VM_HIGHER_HALF;
}

PER_CPU_VAR(unsigned long tlb_nr_invals) = 0;
PER_CPU_VAR(unsigned long nr_tlb_shootdowns) = 0;

struct mm_shootdown_info
{
	unsigned long addr;
	size_t pages;
	mm_address_space *mm;
};

void x86_invalidate_tlb(void *context)
{
	auto info = (mm_shootdown_info *) context;
	auto addr = info->addr;
	auto pages = info->pages;
	auto addr_space = info->mm;

	auto curr_thread = get_current_thread();

	if(is_higher_half(addr) || (curr_thread->owner && &curr_thread->owner->address_space == addr_space))
	{
		paging_invalidate((void *) addr, pages);
		add_per_cpu(tlb_nr_invals, 1);
	}
}

void mmu_invalidate_range(unsigned long addr, size_t pages, mm_address_space *mm)
{
	add_per_cpu(nr_tlb_shootdowns, 1);
	mm_shootdown_info info{addr, pages, mm};

	auto our_cpu = get_cpu_nr();
	cpumask mask;
	
	if(addr >= VM_HIGHER_HALF)
	{
		mask = cpumask::all_but_one(our_cpu);
	}
	else
	{
		mask = *(cpumask *) mm->active_mask;
		mask.remove_cpu(our_cpu);
	}
	

	smp::sync_call_with_local(x86_invalidate_tlb, &info, mask, x86_invalidate_tlb, &info);
}
