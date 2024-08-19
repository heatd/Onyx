/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_VM_H
#define _ONYX_VM_H

#include <lib/binary_search_tree.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <onyx/interval_tree.h>
#include <onyx/list.h>
#include <onyx/mm_address_space.h>
#include <onyx/mutex.h>
#include <onyx/paging.h>
#include <onyx/scheduler.h>
#include <onyx/spinlock.h>
#include <onyx/types.h>

#include <platform/page.h>
#include <platform/vm.h>
#include <platform/vm_layout.h>

__BEGIN_CDECLS

#if defined(__i386__)
#define KERNEL_VIRTUAL_BASE 0xC0000000
#elif defined(__x86_64__)
#define KERNEL_VIRTUAL_BASE 0xFFFFFFFF80000000
#elif defined(__riscv)
#define KERNEL_VIRTUAL_BASE 0xffffffff00000000
#elif defined(__aarch64__)
#define KERNEL_VIRTUAL_BASE 0xffffffff80000000
#endif

#define VM_TYPE_REGULAR     (0)
#define VM_TYPE_STACK       (1)
#define VM_TYPE_SHARED      (2)
#define VM_TYPE_HEAP        (3)
#define VM_TYPE_HW          (4)
#define VM_TYPE_FILE_BACKED (5)
#define VM_TYPE_MODULE      (6)

#define VM_READ          (1 << 0)
#define VM_WRITE         (1 << 1)
#define VM_EXEC          (1 << 2)
#define VM_USER          (1 << 3)
#define VM_NOCACHE       (1 << 4)
#define VM_WRITETHROUGH  (1 << 5)
#define VM_WC            (1 << 6)
#define VM_WP            (1 << 7)
#define VM_DONT_MAP_OVER (1 << 8)
#define VM_NOFLUSH       (1 << 9)
#define VM_SHARED        (1 << 10)

/* Internal flags used by the mm code */
#define __VM_CACHE_TYPE_REGULAR     0
#define __VM_CACHE_TYPE_UNCACHED    1
#define __VM_CACHE_TYPE_WT          2
#define __VM_CACHE_TYPE_WC          3
#define __VM_CACHE_TYPE_WP          4
#define __VM_CACHE_TYPE_UNCACHEABLE 5

static inline unsigned long vm_prot_to_cache_type(uint64_t prot)
{
    if (prot & VM_NOCACHE)
        return __VM_CACHE_TYPE_UNCACHED;
    else if (prot & VM_WRITETHROUGH)
        return __VM_CACHE_TYPE_WT;
    else if (prot & VM_WC)
        return __VM_CACHE_TYPE_WC;
    else if (prot & VM_WP)
        return __VM_CACHE_TYPE_WP;
    else
        return __VM_CACHE_TYPE_REGULAR;
}

#define VM_KERNEL             (1 << 0)
#define VM_ADDRESS_USER       (1 << 1)
#define VM_FULL_ADDRESS_SPACE (1 << 2)

#define PHYS_TO_VIRT(x) (void *) ((uintptr_t) (x) + PHYS_BASE)

#define VM_PFNMAP (1 << 1)

struct vm_object;
struct vm_pf_context;

struct vm_operations
{
    int (*fault)(struct vm_pf_context *ctx);
};

extern const struct vm_operations anon_vmops;
extern const struct vm_operations file_vmops;

struct anon_vma;

/**
 * @brief A VM region is a segment of an address space which is mapped and has some
 * particular metadata in common. These are stored in an mm_address_space and are managed by
 * mmap-like functions (like vm_mmap or vmalloc), mprotect-like functions (like vm_mprotect) and
 * munmap like functions (like vm_munmap).
 *
 */
struct vm_area_struct
{
    unsigned long vm_start;
    unsigned long vm_end;

    union {
        /* TODO: Can we union this with something else? */
        struct list_head vm_detached_node;
    };

    int vm_flags;
    struct mm_address_space *vm_mm;
    const struct vm_operations *vm_ops;
    struct file *vm_file;
    off_t vm_offset;
    struct vm_object *vm_obj;
    struct interval_tree_node vm_objhead;
    struct anon_vma *anon_vma;
    struct list_head anon_vma_node;
};

static inline unsigned long vma_pages(const struct vm_area_struct *vma)
{
    return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}

static inline bool vma_shared(const struct vm_area_struct *vma)
{
    return vma->vm_flags & VM_SHARED;
}

static inline bool vma_private(const struct vm_area_struct *vma)
{
    return !vma_shared(vma);
}

#define VM_OK      0x0
#define VM_SIGBUS  SIGBUS
#define VM_SIGSEGV SIGSEGV

#define VM_BAD_PERMISSIONS (1 << 0)

struct fault_info
{
    uintptr_t fault_address;
    bool write;
    bool read;
    bool exec;
    bool user;
    uintptr_t ip;
    int signal;
    int error_info;
};

struct vm_object;
struct mm_address_space;

/**
 * @brief Initialises the early architecture dependent parts of the VM subsystem.
 *
 */
void vm_init();

/**
 * @brief Initialises the architecture independent parts of the VM subsystem.
 *
 */
void vm_late_init();

#ifdef __cplusplus

/**
 * @brief Creates a new address space.
 *
 * @param addr_space A pointer to the new address space.
 * @param original Original address space - defaults to the current one
 * @return 0 on success, negative on error.
 */
int vm_clone_as(struct mm_address_space *addr_space, struct mm_address_space *original = NULL);

#endif

/**
 * @brief Fork the current address space into a new address space.
 *
 * @param addr_space The new address space.
 * @return 0 on success, negative on error.
 */
int vm_fork_address_space(struct mm_address_space *addr_space);

/**
 * @brief Loads an address space
 *
 * @param aspace Address space to load
 * @param cpu CPU we're on
 */
void vm_load_aspace(struct mm_address_space *aspace, unsigned int cpu);

/**
 * @brief Sets the current address space, and returns the old one
 *
 * @param aspace Address space to set and load
 * @return The old address space
 */
struct mm_address_space *vm_set_aspace(struct mm_address_space *aspace);

/**
 * @brief Changes permissions of a memory area.
 * Note: Deprecated and should not be used.
 * @param range Start of the range.
 * @param pages Number of pages.
 * @param perms New permissions.
 */
__deprecated void vm_change_perms(void *range, size_t pages, int perms);

/**
 * @brief Retrieves the fallback paging directories.
 * The kernel has a fallback pgd on which process fall back to right before freeing
 * its own pgd, during process destruction.
 *
 * @return void* The fallback pgd.
 */
void *vm_get_fallback_pgd();

/**
 * @brief Allocates a range of virtual memory for kernel purposes.
 * This memory is all prefaulted and cannot be demand paged nor paged out.
 *
 * @param pages The number of pages.
 * @param type The type of allocation.
 * @param perms The permissions on the allocation.
 * @param gfp_flags GFP flags
 * @return A pointer to the new allocation, or NULL with errno set on failure.
 */
void *vmalloc(size_t pages, int type, int perms, unsigned int gfp_flags);

/**
 * @brief Frees a region of memory previously allocated by vmalloc.
 *
 * @param ptr A pointer to the allocation.
 * @param pages The number of pages it consists in.
 */
void vfree(void *ptr, size_t pages);

/**
 * @brief Handles a page fault.
 *
 * @param info A pointer to a fault_info structure.
 * @return 0 on success or negative error codes.
 */
int vm_handle_page_fault(struct fault_info *info);

/**
 * @brief Does the fatal page fault procedure.
 * When a user fault, kills the process; else, panics.
 *
 * @param info A pointer to a fault_info structure.
 */
void vm_do_fatal_page_fault(struct fault_info *info);

/**
 * @brief Creates a mapping of MMIO memory.
 * Note: This function does not add any implicit caching behaviour by default.
 *
 * @param phys The start of the physical range.
 * @param size The size of the physical range.
 * @param flags Permissions on the new region.
 * @return A pointer to the new mapping, or NULL with errno set on error.
 */
void *mmiomap(void *phys, size_t size, size_t flags);

/**
 * @brief Unmaps a mmio region
 *
 * @param virt Virtual address
 * @param size Size
 */
void mmiounmap(void *virt, size_t size);

/**
 * @brief Destroys an address space.
 *
 * @param mm A pointer to a valid mm_address_space.
 */
void vm_destroy_addr_space(struct mm_address_space *mm);

/**
 * @brief Sanitises the address.
 * It does so by comparing it with a number of invalid ranges of
 * virtual memory, some of which may be arch dependent.
 * To be used by program loaders.
 *
 * @param address The address to-be-tested.
 * @param pages The size of the desired range.
 * @return 0 if it's valid, negative if not.
 */
int vm_sanitize_address(void *address, size_t pages);

/**
 * @brief Generates a new mmap base, taking into account arch-dependent addresses and possibly
 * KASLR.
 *
 * @return The new mmap base. Note: This is not a valid pointer, but the starting point
 *         for mmap allocations.
 */
void *vm_gen_mmap_base();

/**
 * @brief Generates a new brk base, taking into account arch-dependent addresses and possibly KASLR.
 *
 * @return The new brk base. Note: This is not a valid pointer, but the starting point
 *         for brk allocations.
 */
void *vm_gen_brk_base();

/**
 * @brief Initialises sysfs nodes for the vm subsystem.
 *
 */
void vm_sysfs_init();

/**
 * @brief Copies data to user space.
 *
 * @param usr The destination user space pointer.
 * @param data The source kernel pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
ssize_t copy_to_user(void *usr, const void *data, size_t len);

/**
 * @brief Copies data from user space.
 *
 * @param data The destionation kernel pointer.
 * @param usr The source user space pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
ssize_t copy_from_user(void *data, const void *usr, size_t len);

/**
 * @brief Memsets user space memory.
 *
 * @param data The destionation user space pointer.
 * @param data The destionation kernel pointer.
 * @param len The length of the copy, in bytes.
 * @return 0 if successful, negative error codes if error'd.
 *         At the time of writing, the only possible error return is -EFAULT.
 */
ssize_t user_memset(void *data, int val, size_t len);

/**
 * @brief Sets up backing for a newly-mmaped region.
 *
 * @param region A pointer to a vm_area_struct.
 * @param pages The size of the region, in pages.
 * @param is_file_backed True if file backed.
 * @return 0 on success, negative for errors.
 */
int vma_setup_backing(struct vm_area_struct *region, size_t pages, bool is_file_backed);

/**
 * @brief Updates the memory map's ranges.
 * Used in arch dependent early boot procedures when architectures
 * have variable address space sizes. See example uses of this
 * function in arch/x86_64.
 *
 * @param new_kernel_space_base The new virtual memory base.
 */
void vm_update_addresses(uintptr_t new_kernel_space_base);

/**
 * @brief Generate a ASLR'd address.
 * Takes into account base and bits.
 *
 * @param base The base address.
 * @param bits The number of bits that can be randomised.
 * @return The randomised address.
 */
uintptr_t vm_randomize_address(uintptr_t base, uintptr_t bits);

/**
 * @brief Map a specific number of pages onto a virtual address.
 * Should only be used by MM code since it does not touch vm_area_structs, only
 * MMU page tables.
 *
 * @param virt The virtual address.
 * @param phys The start of the physical range.
 * @param size The size of the mapping, in bytes.
 * @param flags The permissions on the mapping.
 *
 * @return NULL on error, virt on success.
 */
void *map_pages_to_vaddr(void *virt, void *phys, size_t size, size_t flags);

/**
 * @brief Map a specific number of pages onto a virtual address.
 * Should only be used by MM code since it does not touch vm_area_structs, only
 * MMU page tables.
 *
 * @param as   The target address space.
 * @param virt The virtual address.
 * @param phys The start of the physical range.
 * @param size The size of the mapping, in bytes.
 * @param flags The permissions on the mapping.
 *
 * @return NULL on error, virt on success.
 */
void *__map_pages_to_vaddr(struct mm_address_space *as, void *virt, void *phys, size_t size,
                           size_t flags);

/**
 * @brief Determines if a mapping is file backed.
 *
 * @param region A pointer to the vm_area_struct.
 * @return True if file backed, false if not.
 */
bool is_file_backed(struct vm_area_struct *region);

/**
 * @brief Traverses the kernel's memory map and prints information.
 *
 */
void vm_print_map();

/**
 * @brief Traverses the current process's memory map and prints information.
 *
 */
void vm_print_umap();

/**
 * @brief Changes memory protection of a memory range.
 *
 * @param as The target address space.
 * @param __addr The pointer to the start of the memory range.
 * @param size The size of the memory range, in bytes.
 * @param prot The desired protection flags. Valid flags are PROT_*, as in mmap(2)
               or mprotect(2).
 * @return 0 on success, negative error codes.
 */
int vm_mprotect(struct mm_address_space *as, void *__addr, size_t size, int prot);

struct file;
/**
 * @brief Creates a new user-space mapping.
 * Note: This is mmap(2)'s backend and therefore, most semantics are shared
 * between the two.
 *
 * @param addr An optional address hint.
 * @param length The length of the mapping, in bytes.
 * @param prot The desired protection flags (see PROT_* as in mmap(2)).
 * @param flags The mapping flags (see MAP_* as in mmap(2)).
 * @param file An optional pointer to a file, if it is a file mapping.
 * @param off The offset into the file, if it is a file mapping.
 * @return A pointer to the new memory mapping, or an ERR_PTR on error.
 */
void *vm_mmap(void *addr, size_t length, int prot, int flags, struct file *file, off_t off);

struct tlb_shootdown
{
    unsigned long addr;
    size_t pages;
};

/**
 * @brief Invalidates a range of memory in the current address space.
 * This function handles TLB shootdowns on its own.
 *
 * @param addr The start of the range.
 * @param pages The size of the range, in pages.
 */
void vm_invalidate_range(unsigned long addr, size_t pages);

struct process;

/**
 * @brief Allocates a new mapping and maps a list of pages.
 *
 * @param pl The list of pages.
 * @param size The size of the mapping, in bytes.
 * @param prot The desired protection flags.
 * @return A pointer to the new mapping, or NULL if it failed.
 */
void *map_page_list(struct page *pl, size_t size, uint64_t prot);

/**
 * @brief Sets up a new address space on \p mm
 *
 * @param mm A pointer to the new address space.
 * @return 0 on success, negative error codes.
 */
int vm_create_address_space(struct mm_address_space *mm);

/**
 * @brief Free the architecture dependent parts of the address space.
 * Called on address space destruction.
 *
 * @param mm The to-be-destroyed address space.
 */
void vm_free_arch_mmu(struct arch_mm_address_space *mm);

/**
 * @brief Loads a new address space.
 *
 * @param mm The to-be-loaded address space.
 */
void vm_load_arch_mmu(struct arch_mm_address_space *mm);

/**
 * @brief Saves the current address space in \p mm
 *
 * @param mm A pointer to a valid mm_address_space.
 */
void vm_save_current_mmu(struct mm_address_space *mm);

/**
 * @brief Unmaps a memory range.
 *
 * @param as The target address space.
 * @param __addr The start of the memory range.
 * @param size The size of the memory range, in bytes.
 * @return 0 on success, or negative error codes.
 */
int vm_munmap(struct mm_address_space *as, void *__addr, size_t size);

/**
 * @brief Sets up the brk region for a new process.
 *
 * @param mm The target address space.
 * @return 0 on success, or negative error codes.
 */
int vm_create_brk(struct mm_address_space *mm);

/**
 * @brief Aligns a pointer to the next page boundary.
 *
 * @param ptr The target pointer.
 * @return A page aligned pointer.
 */
static inline void *page_align_up(void *ptr)
{
    uintptr_t i = (uintptr_t) ptr;
    i = (i + PAGE_SIZE - 1) & -PAGE_SIZE;
    return (void *) i;
}

/**
 * @brief Calculates the number of pages given a number of bytes.
 *
 * @param size The number of bytes.
 * @return A number of pages.
 */
static inline size_t vm_size_to_pages(size_t size)
{
    size_t pages = size >> PAGE_SHIFT;
    if (size & (PAGE_SIZE - 1))
        pages++;
    return pages;
}

/**
 * @brief Calculates the number of pages given a non-static page_size and page_shift
 *
 * @param size The number of bytes.
 * @param page_size The page size (must be power of 2).
 * @param page_shift The page shift.
 * @return The number of pages.
 */
static inline size_t __vm_size_to_pages(size_t size, size_t page_size, size_t page_shift)
{
    size_t pages = size >> page_shift;
    if (size & (page_size - 1))
        pages++;
    return pages;
}

extern struct mm_address_space kernel_address_space;

struct kernel_limits
{
    uintptr_t start_phys, start_virt;
    uintptr_t end_phys, end_virt;
};

/**
 * @brief Retrieves the kernel's limits in physical memory and virtual memory.
 *
 * @param l A pointer to a kernel_limits object where the limits will be placed.
 */
void get_kernel_limits(struct kernel_limits *l);

void vm_wp_page(struct mm_address_space *mm, void *vaddr);

/**
 * @brief Invalidates a memory range.
 *
 * @param addr The start of the memory range.
 * @param pages The size of the memory range, in pages.
 * @param mm The target address space.
 */
void mmu_invalidate_range(unsigned long addr, size_t pages, struct mm_address_space *mm);

#define VM_FUTURE_PAGES (1 << 0)
#define VM_LOCK         (1 << 1)
#define VM_UNLOCK       (1 << 2)

/**
 * @brief Changes the current address limit.
 * The address limit is the largest address the user memory primitives (e.g copy_to_user,
 * copy_from_user) can touch.
 *
 * @param limit The new address limit.
 * @return The old address limit.
 */
static inline unsigned long thread_change_addr_limit(unsigned long limit)
{
    struct thread *t = get_current_thread();
    if (!t)
        return VM_KERNEL_ADDR_LIMIT;

    unsigned long r = t->addr_limit;
    t->addr_limit = limit;

    return r;
}

#ifdef __cplusplus
/**
 * @brief RAII wrapper for thread_change_addr_limit
 *
 */
class auto_addr_limit
{
    unsigned long old_;

public:
    auto_addr_limit(unsigned long new_limit)
    {
        old_ = thread_change_addr_limit(new_limit);
    }

    ~auto_addr_limit()
    {
        thread_change_addr_limit(old_);
    }

    auto_addr_limit() = delete;
    CLASS_DISALLOW_COPY(auto_addr_limit);
    CLASS_DISALLOW_MOVE(auto_addr_limit);
};

#endif

#define GPP_READ  (1 << 0)
#define GPP_WRITE (1 << 1)
#define GPP_USER  (1 << 2)

// GPP_ACCESS flags documentation

// The GPP access was a success
#define GPP_ACCESS_OK     (1 << 0)
// There was a fault(the permissions don't match or we ran out of memory) accessing the pages
#define GPP_ACCESS_FAULT  (1 << 1)
// One or more pages are not normal memory
#define GPP_ACCESS_PFNMAP (1 << 2)
// One or more pages are part of a shared region
#define GPP_ACCESS_SHARED (1 << 3)

/**
 * @brief Gets the physical pages that map to a virtual region.
 * This function also handles COW.
 *
 * @param addr The desired virtual address.
 * @param flags Flags (see GPP_READ, WRITE and USER).
 * @param pages A pointer to an array of struct page *.
 * @param nr The number of pages of the virtual address range.
 * @return A bitmask of GPP_ACCESS_* flags; see the documentation for those
 *         for more information.
 */
int get_phys_pages(void *addr, unsigned int flags, struct page **pages, size_t nr);

/**
 * @brief Directly mprotect a page in the paging tables.
 * Called by core MM code and should not be used outside of it.
 * This function handles any edge cases like trying to re-apply write perms on
 * a write-protected page.
 *
 * @param as The target address space.
 * @param addr The virtual address of the page.
 * @param old_prots The old protection flags.
 * @param new_prots The new protection flags.
 */
void vm_mmu_mprotect_page(struct mm_address_space *as, void *addr, int old_prots, int new_prots);

/**
 * @brief Loads the fallback paging tables.
 *
 */
void vm_switch_to_fallback_pgd();

/**
 * @brief Retrieves a pointer to the zero page.
 *
 * @return Pointer to the zero page's struct page.
 */
struct page *vm_get_zero_page();

/**
 * @brief Transforms a file-backed region into an anonymously backed one.
 *
 * @param region A pointer to the vm_area_struct.
 */
void vm_make_anon(struct vm_area_struct *region);

/**
 * @brief Verifies the address space's accounting (RSS, PT Size)
 *
 * @param as The address space to verify.
 */
void mmu_verify_address_space_accounting(struct mm_address_space *as);

struct sysfs_object;

/**
 * @brief Create vm/mm sysfs files and dirs
 *
 * @param obj Object
 */
void vm_create_sysfs(struct sysfs_object *mmobj);

/**
 * @brief Initialize the vmalloc allocator
 *
 * @param start Start of the vmalloc region
 * @param length Length of the vmalloc region
 */
void vmalloc_init(unsigned long start, unsigned long length);

/**
 * @brief Get the backing pages behind a vmalloc region
 *
 * @param ptr Pointer to the region (must be mapped and not MMIO)
 * @return List of pages
 */
struct page *vmalloc_to_pages(void *ptr);

/**
 * @brief Check if a given VMA is a PFNMAP vma
 *
 * @param vma VMA to check. If null, pretend we're PFNMAP
 * @return True if PFNMAP, else false.
 */
static inline bool vma_is_pfnmap(struct vm_area_struct *vma)
{
    return vma == NULL;
}

void vm_do_mmu_mprotect(struct mm_address_space *as, void *address, size_t nr_pgs, int old_prots,
                        int new_prots);

__END_CDECLS

#ifdef __cplusplus

/**
 * @brief Calls the specified function \p func on every region of the address space \p as.
 *
 * @param as A reference to the target address space.
 * @param func The callback.
 */
template <typename Callable>
inline void vm_for_every_region(mm_address_space &as, Callable func)
{
    vm_area_struct *entry;
    unsigned long index = 0;
    void *entry_;
    mt_for_each (&as.region_tree, entry_, index, -1UL)
    {
        entry = (vm_area_struct *) entry_;
        if (!func(entry))
            break;
    }
}

#endif

#endif
