/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _VM_H
#define _VM_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <onyx/paging.h>
#include <onyx/spinlock.h>
#include <onyx/mm/vm_object.h>

#ifdef __x86_64__
#include <onyx/x86/page.h>
#endif

#include <sys/types.h>
#if defined (__i386__)
	#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined (__x86_64__)
	#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#endif

#define VM_TYPE_REGULAR		(0)
#define VM_TYPE_STACK 		(1)
#define VM_TYPE_SHARED 		(2)
#define VM_TYPE_HEAP 		(3)
#define VM_TYPE_HW 		(4)
#define VM_TYPE_FILE_BACKED	(5)
#define VM_TYPE_MODULE		(6)

#define VM_WRITE 		(1 << 0)
#define VM_NOEXEC 		(1 << 1)
#define VM_USER 		(1 << 2)
#define VM_NOCACHE		(1 << 3)
#define VM_WRITETHROUGH		(1 << 4)
#define VM_WC			(1 << 5)
#define VM_WP			(1 << 6)
#define VM_DONT_MAP_OVER	(1 << 7)

/* Internal flags used by the mm code */
#define __VM_CACHE_TYPE_REGULAR 	0
#define __VM_CACHE_TYPE_UNCACHED	1
#define __VM_CACHE_TYPE_WT		2
#define __VM_CACHE_TYPE_WC		3
#define __VM_CACHE_TYPE_WP		4
#define __VM_CACHE_TYPE_UNCACHEABLE 	5


static inline unsigned long vm_prot_to_cache_type(uint64_t prot)
{
	if(prot & VM_NOCACHE)
		return __VM_CACHE_TYPE_UNCACHEABLE;
	else if(prot & VM_WRITETHROUGH)
		return __VM_CACHE_TYPE_WT;
	else if(prot & VM_WC)
		return __VM_CACHE_TYPE_WC;
	else if(prot & VM_WP)
		return __VM_CACHE_TYPE_WP;
	else
		return __VM_CACHE_TYPE_REGULAR;
}

#define VM_KERNEL 		(1)
#define VM_ADDRESS_USER		(1 << 1)

#define VM_HIGHER_HALF 0xffff800000000000
#define PHYS_TO_VIRT(x) (void*)((uintptr_t) (x) + PHYS_BASE)

#define VM_COW				(1 << 1)
#define VM_USING_MAP_SHARED_OPT		(1 << 2)

struct vm_region
{
	uintptr_t base;
	size_t pages;
	int rwx;
	int type;
	int mapping_type;
	struct file_description *fd;
	off_t offset;
	int flags;
	struct vm_object *vmo;
	struct mm_address_space *mm;

	struct vm_region *next_mapping;
	uintptr_t caller;
};

#define VM_OK			0x0
#define VM_SIGBUS		0x1
#define VM_SIGSEGV		0x2

struct fault_info
{
	uintptr_t fault_address;
	bool write;
	bool read;
	bool exec;
	bool user;
	uintptr_t ip;
	int error;
};

struct rb_tree;
struct vm_object;

struct mm_address_space
{
	struct process *process;
	/* Virtual address space AVL tree */
	struct rb_tree *area_tree;
	unsigned long start;
	unsigned long end;
	struct spinlock vm_spl;

	/* mmap(2) base */
	void *mmap_base;

	/* Process' brk */
	void *brk;

	struct spinlock private_vmo_lock;
	struct vm_object *vmo_head, *vmo_tail;
#ifdef __x86_64__
	PML4* cr3;
#endif
};

#ifdef __cplusplus
extern "C" {
#endif

void vm_init(void);
void vm_late_init(void);
struct vm_region *vm_allocate_virt_region(uint64_t flags, size_t pages,
	uint32_t type, uint64_t prot);
struct page *vm_map_range(void *range, size_t pages, uint64_t flags);
void vm_unmap_range(void *range, size_t pages);
void vm_destroy_mappings(void *range, size_t pages);
struct vm_region *vm_reserve_address(void *addr, size_t pages, uint32_t type,
	uint64_t prot);
struct vm_region *vm_find_region(void *addr);
int vm_clone_as(struct mm_address_space *addr_space);
int vm_fork_as(struct mm_address_space *addr_space);
void vm_change_perms(void *range, size_t pages, int perms);
void *vm_get_fallback_cr3(void);
int vm_check_pointer(void *addr, size_t needed_space);
void *vmalloc(size_t pages, int type, int perms);
void vfree(void *ptr, size_t pages);
int vm_handle_page_fault(struct fault_info *info);
void vm_do_fatal_page_fault(struct fault_info *info);
void *vmalloc(size_t pages, int type, int perms);
void *mmiomap(void *phys, size_t size, size_t flags);
void vm_destroy_addr_space(struct mm_address_space *mm);
int vm_sanitize_address(void *address, size_t pages);
void *vm_gen_mmap_base(void);
void *vm_gen_brk_base(void);
void vm_sysfs_init(void);
int vm_mark_cow(struct vm_region *zone);
struct vm_region *vm_find_region_and_writable(void *usr);
ssize_t copy_to_user(void *usr, const void *data, size_t len);
ssize_t copy_from_user(void *data, const void *usr, size_t len);
void vm_update_addresses(uintptr_t new_kernel_space_base);
uintptr_t vm_randomize_address(uintptr_t base, uintptr_t bits);
void *map_pages_to_vaddr(void *virt, void *phys, size_t size, size_t flags);
void *get_user_pages(uint32_t type, size_t pages, size_t prot);
void *get_pages(size_t flags, uint32_t type, size_t pages, size_t prot,
	uintptr_t alignment);
bool is_mapping_shared(struct vm_region *);
bool is_file_backed(struct vm_region *);
int vm_flush(struct vm_region *entry);
void vm_print_map(void);
void vm_print_umap();
int vm_mprotect(struct mm_address_space *as, void *__addr, size_t size, int prot);

struct tlb_shootdown
{
	unsigned long addr;
	size_t pages;
};

void vm_do_shootdown(struct tlb_shootdown *inv_data);
void vm_invalidate_range(unsigned long addr, size_t pages);

#define VM_MMAP_PRIVATE		(1 << 0)
#define VM_MMAP_SHARED		(1 << 1)
#define VM_MMAP_FIXED		(1 << 2)

void *create_file_mapping(void *addr, size_t pages, int flags,
	int prot, struct file_description *fd, off_t off);

void *map_user(void *addr, size_t pages, uint32_t type, uint64_t prot);

struct process;

void *vm_map_page(struct process *proc, uint64_t virt, uint64_t phys,
	uint64_t prot);
void *__map_pages_to_vaddr(struct process *process, void *virt, void *phys,
		size_t size, size_t flags);
void *map_page_list(struct page *pl, size_t size, uint64_t prot);

int vm_create_address_space(struct process *process, void *cr3);

int vm_munmap(struct mm_address_space *as, void *__addr, size_t size);


static inline void *page_align_up(void *ptr)
{
	uintptr_t i = (uintptr_t) ptr;
	i = (i + PAGE_SIZE-1) & -PAGE_SIZE;
	return (void *) i;
}

static inline size_t vm_align_size_to_pages(size_t size)
{
	size_t pages = size >> PAGE_SHIFT;
	if(size & (PAGE_SIZE-1))
		pages++;
	return pages;
}

extern struct mm_address_space kernel_address_space;
void vm_for_every_region(struct mm_address_space *as, bool (*func)(struct vm_region *region));

struct kernel_limits
{
	uintptr_t start_phys, start_virt;
	uintptr_t end_phys, end_virt;
};

void get_kernel_limits(struct kernel_limits *l);


#ifdef __cplusplus
}
#endif
#endif
