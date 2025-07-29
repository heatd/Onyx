/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include <onyx/arch.h>
#include <onyx/compiler.h>
#include <onyx/copy.h>
#include <onyx/cpu.h>
#include <onyx/dentry.h>
#include <onyx/err.h>
#include <onyx/file.h>
#include <onyx/filemap.h>
// #include <onyx/gen/trace_vm.h>
#include <onyx/log.h>
#include <onyx/majorminor.h>
#include <onyx/mm/kasan.h>
#include <onyx/mm/shmem.h>
#include <onyx/mm/slab.h>
#include <onyx/mm/vm_object.h>
#include <onyx/page.h>
#include <onyx/pagecache.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/pgtable.h>
#include <onyx/proc.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/rmap.h>
#include <onyx/seq_file.h>
#include <onyx/spinlock.h>
#include <onyx/swap.h>
#include <onyx/sysfs.h>
#include <onyx/timer.h>
#include <onyx/user.h>
#include <onyx/utils.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>
#include <onyx/vm_fault.h>
#include <onyx/vm_layout.h>

#include <uapi/fcntl.h>
#include <uapi/memstat.h>

#include "vma_internal.h"

static bool enable_aslr = true;

uintptr_t high_half = arch_high_half;

/* These addresses are either absolute, or offsets, depending on the architecture.
 * The corresponding arch/ code is responsible for patching these up using
 * vm_update_addresses.
 */
uintptr_t vmalloc_space = arch_vmalloc_off;

void kmalloc_init();
void vm_remove_region(struct mm_address_space *as, struct vm_area_struct *region);
int __vm_munmap(struct mm_address_space *as, void *__addr, size_t size);
static bool limits_are_contained(struct vm_area_struct *reg, unsigned long start,
                                 unsigned long limit);
static bool vm_mapping_is_cow(struct vm_area_struct *entry);

/* TODO */
#undef REQUIRES_SHARED
#undef REQUIRES
#undef EXCLUDES
#define REQUIRES_SHARED(...)
#define REQUIRES(...)
#define EXCLUDES(...)

struct vm_area_struct *vm_search(struct mm_address_space *mm, void *addr, size_t length)
    REQUIRES_SHARED(mm->vm_lock);
static void vma_pre_adjust(struct vm_area_struct *vma);

/**
 * @brief Finds a vm region.
 *
 * @param as Address space
 * @param addr An address inside the region.
 * @return A pointer to the region, or NULL if it doesn't exist.
 */
__always_inline struct vm_area_struct *vm_find_region(struct mm_address_space *as, void *addr)
    REQUIRES_SHARED(as->vm_lock)
{
    return vm_search(as, addr, 2);
}

bool vm_test_vs_rlimit(const struct mm_address_space *as, ssize_t diff)
{
    /* The kernel doesn't have resource limits */
    if (as == &kernel_address_space)
        return true;
    /* Decreasing the resource usage doesn't respect limits */
    if (diff < 0)
        return true;
    return rlim_get_cur(RLIMIT_AS) >= as->virtual_memory_size + (size_t) diff;
}

struct mm_address_space kernel_address_space = {
    .page_table_lock = __SPIN_LOCK_UNLOCKED(kernel_address_space.page_table_lock),
    .region_tree = MTREE_INIT(region_tree, MT_FLAGS_ALLOC_RANGE | MT_FLAGS_LOCK_EXTERN),
    .mm_count = REFCOUNT_INIT(2),
    .mm_users = REFCOUNT_INIT(2),
};

static struct page *vm_zero_page = NULL;
static struct slab_cache *vm_area_struct_cache = NULL;

static inline struct vm_area_struct *vma_alloc(void)
{
    return kmem_cache_alloc(vm_area_struct_cache, GFP_KERNEL);
}

static inline void vma_free(struct vm_area_struct *region)
{
    kmem_cache_free(vm_area_struct_cache, (void *) region);
}

#ifdef CONFIG_DEBUG_MM_MMAP
static void validate_mm_tree(struct mm_address_space *mm)
{
    VMA_ITERATOR(vmi, mm, 0, -1UL);
    void *entry_;
    size_t counting_vss = 0;
    size_t counting_sss = 0;
    mas_for_each(&vmi.mas, entry_, -1UL)
    {
        struct vm_area_struct *vma = (struct vm_area_struct *) entry_;
        if (vma->vm_start != vmi.mas.index || vma->vm_end != vmi.mas.last + 1)
        {
            pr_err("mm: vma bounds [%016lx, %016lx] do not match maple tree [%016lx, %016lx]\n",
                   vma->vm_start, vma->vm_end, vmi.mas.index, vmi.mas.last + 1);
            goto print_tree;
        }

        counting_vss += vma->vm_end - vma->vm_start;
        if (vma_shared(vma))
            counting_sss += vma->vm_end - vma->vm_start;
    }

    if (counting_vss != mm->virtual_memory_size)
    {
        pr_err("mm: mm %p has wrong vss (%lx vs %lx bytes)\n", mm, counting_vss,
               mm->virtual_memory_size);
        goto print_tree;
    }

    if (counting_sss != mm->shared_set_size)
    {
        pr_err("mm: mm %p has wrong shared set size (%lx vs %lx bytes)\n", mm, counting_sss,
               mm->shared_set_size);
        goto print_tree;
    }

    vmi_destroy(&vmi);
    return;
print_tree:
    pr_err("mm: dumping vmas for mm %p...\n", mm);
    mas_set(&vmi.mas, 0);
    mas_for_each(&vmi.mas, entry_, -1UL)
    {
        struct vm_area_struct *vma = (struct vm_area_struct *) entry_;
        const char *name = "[anon]";
        if (vma->vm_file)
            name = vma->vm_file->f_dentry->d_name;
        pr_err("  [%016lx, %016lx] vma ([%016lx, %016lx] maple tree) flags %x  %s\n", vma->vm_start,
               vma->vm_end, vmi.mas.index, vmi.mas.last + 1, vma->vm_flags, name);
    }

    pr_err("mm: dump done.\n");
    __WARN();
    vmi_destroy(&vmi);
}

#else

#define validate_mm_tree(mm) \
    do                       \
    {                        \
    } while (0)

#endif

bool vm_insert_region(struct mm_address_space *as, struct vm_area_struct *region)
{
    return mtree_insert_range(&as->region_tree, region->vm_start, region->vm_end - 1, region,
                              GFP_KERNEL) == 0;
}

static unsigned long vm_get_base_address(uint64_t flags, uint32_t type);

static int vm_alloc_address(struct vma_iterator *vmi, u64 flags, size_t size, int type)
    REQUIRES(vmi->mm->vm_lock)
{
    struct mm_address_space *mm = vmi->mm;
    unsigned long min = vm_get_base_address(flags, type);

    if (min < mm->start)
        min = mm->start;
    if (mas_empty_area(&vmi->mas, min, mm->end, size) != 0)
        return -ENOMEM;

    unsigned long new_base = vmi->mas.index;
    CHECK((new_base & (PAGE_SIZE - 1)) == 0);
    if (!arch_vm_validate_mmap_region(new_base, size, flags))
        return -ENOMEM;

    vmi->index = vmi->mas.index;
    vmi->end = vmi->mas.last;
    return 0;
}

void vm_addr_init()
{
    kernel_address_space.start = VM_HIGHER_HALF;
    kernel_address_space.end = UINTPTR_MAX;
}

static inline bool is_higher_half(void *address)
{
    return (uintptr_t) address > VM_HIGHER_HALF;
}

/**
 * @brief Initialises the early architecture dependent parts of the VM subsystem.
 *
 */
void vm_init()
{
    paging_init();
    arch_vm_init();

    // Reserve the kernel in the boot memory map
    struct kernel_limits limits;
    get_kernel_limits(&limits);

    bootmem_reserve(limits.start_phys, limits.end_phys - limits.start_phys);
}

void maple_tree_init();

/**
 * @brief Initialises the architecture independent parts of the VM subsystem.
 *
 */
void vm_late_init()
{
    /* TODO: This should be arch specific stuff, move this to arch/ */
    const unsigned long vmalloc_noaslr = vmalloc_space;
    vmalloc_space = vm_randomize_address(vmalloc_space, VMALLOC_ASLR_BITS);

    // Initialize vmalloc first. This will feed the rest of the allocators.
    const unsigned long vmalloc_len = VM_VMALLOC_SIZE - (vmalloc_space - vmalloc_noaslr);

    vmalloc_init(vmalloc_space, vmalloc_len);
    // Now initialize slabs for kmalloc

    kmalloc_init();

    maple_tree_init();
    vm_area_struct_cache =
        kmem_cache_create("vm_area_struct", sizeof(struct vm_area_struct), 0, 0, NULL);

    if (!vm_area_struct_cache)
        panic("vm: early boot oom");

    vm_addr_init();

    vm_zero_page = alloc_page(0);
    assert(vm_zero_page != NULL);
}

void do_vm_unmap(struct mm_address_space *as, void *range, size_t pages)
    REQUIRES_SHARED(as->vm_lock)
{
    struct vm_area_struct *entry = vm_find_region(as, range);
    assert(entry != NULL);

    vm_mmu_unmap(entry->vm_mm, range, pages, entry);
}

void __vm_unmap_range(struct mm_address_space *as, void *range, size_t pages)
    REQUIRES_SHARED(as->vm_lock)
{
    do_vm_unmap(as, range, pages);
}

static inline bool inode_requires_wb(struct inode *i)
{
    return true;
}

bool vm_mapping_requires_wb(struct vm_area_struct *reg)
{
    return vma_shared(reg) && reg->vm_file && inode_requires_wb(reg->vm_file->f_ino);
}

bool vm_mapping_is_anon(struct vm_area_struct *reg)
{
    return reg->vm_file == NULL;
}

/**
 * @brief Transforms a file-backed region into an anonymously backed one.
 *
 * @param region A pointer to the vm_area_struct.
 */
void vm_make_anon(struct vm_area_struct *reg)
{
    if (reg->vm_file)
    {
        fd_put(reg->vm_file);
        reg->vm_file = NULL;
    }
}

bool vm_mapping_requires_write_protect(struct vm_area_struct *reg)
{
    return vm_mapping_requires_wb(reg);
}

static void vma_destroy(struct vm_area_struct *region)
{
    /* First, unref things */
    if (region->vm_file)
    {
        fd_put(region->vm_file);
    }

    if (region->vm_obj)
    {
        vmo_remove_mapping(region->vm_obj, region);
        vmo_unref(region->vm_obj);
    }

    if (region->anon_vma)
        anon_vma_unlink(region->anon_vma, region);

    memset_explicit(region, 0xfd, sizeof(struct vm_area_struct));

    vma_free(region);
}

static unsigned long vm_get_base_address(uint64_t flags, uint32_t type)
{
    bool is_kernel_map = flags & VM_KERNEL;
    DCHECK(!is_kernel_map);
    struct mm_address_space *mm = get_current_address_space();

    switch (type)
    {
        case VM_TYPE_SHARED:
        case VM_TYPE_STACK: {
            DCHECK(!is_kernel_map);
            return (uintptr_t) mm->mmap_base;
        }

        default:
        case VM_TYPE_REGULAR: {
            return (uintptr_t) mm->mmap_base;
        }
    }
}

struct vm_area_struct *vm_search(struct mm_address_space *mm, void *addr, size_t length)
    REQUIRES_SHARED(mm->vm_lock)
{
    unsigned long index = (unsigned long) addr;
    void *entry = mt_find(&mm->region_tree, &index, index + length - 1);
    struct vm_area_struct *vma = (struct vm_area_struct *) entry;
    if (vma && vma->vm_start > (unsigned long) addr)
        return NULL;
    return vma;
}

static struct vm_area_struct *__vm_create_region_at(struct mm_address_space *mm, void *addr,
                                                    size_t pages, uint32_t type, uint64_t prot)
    REQUIRES(mm->vm_lock)
{
    /* TODO: remove once sys_mremap gets improved and tested */
    return NULL;
}

/**
 * @brief Creates a new address space.
 *
 * @param addr_space A pointer to the new address space.
 * @return 0 on success, negative on error.
 */
int vm_clone_as(struct mm_address_space *addr_space, struct mm_address_space *original)
{
    if (!original)
        original = get_current_address_space();
    if (!original)
        original = &kernel_address_space;
    rw_lock_read(&original->vm_lock);
    int err = paging_clone_as(addr_space, original);
    rw_unlock_read(&original->vm_lock);
    return err;
}

#define DEBUG_FORK_VM 0
static bool fork_vm_area_struct(struct vm_area_struct *region, struct mm_address_space *mm)
{
    bool is_private;
    bool res;

    struct vm_area_struct *new_region = vma_alloc();
    if (!new_region)
        return false;

    memcpy(new_region, region, sizeof(*region));
    /* TODO: mtree dup */

#if DEBUG_FORK_VM
    printk("Forking [%016lx, %016lx] perms %x\n", region->base,
           region->base + (region->pages << PAGE_SHIFT) - 1, region->rwx);
#endif

    res = vm_insert_region(mm, new_region);

    assert(res == true);

    if (new_region->anon_vma)
        anon_vma_link(new_region->anon_vma, new_region);

    if (new_region->vm_file)
        fd_get(new_region->vm_file);

    is_private = vma_private(new_region);

    if (is_private)
    {
        /* No need to ref the vmo since it was a new vmo created for us while forking. */
        if (new_region->vm_obj)
        {
            vmo_assign_mapping(new_region->vm_obj, new_region);
            vmo_ref(new_region->vm_obj);
        }
    }
    else
    {
        vmo_ref(new_region->vm_obj);
        vmo_assign_mapping(new_region->vm_obj, new_region);
    }

    new_region->vm_mm = mm;

    if (mmu_fork_tables(region, mm) < 0)
        return false;
#ifdef CONFIG_DEBUG_ADDRESS_SPACE_ACCT
    mmu_verify_address_space_accounting(mm);
#endif
    return true;
}

static void addr_space_delete(struct vm_area_struct *region) NO_THREAD_SAFETY_ANALYSIS
{
    // NO_THREAD_SAFETY_ANALYSIS = we can do this without holding the lock, as tear_down_addr_space
    // is called in fork paths.
    do_vm_unmap(region->vm_mm, (void *) region->vm_start, vma_pages(region));

    vma_destroy(region);
}

static void tear_down_addr_space(struct mm_address_space *addr_space)
{
    /*
     * Note: We free the tree first in order to free any forked pages.
     * If we didn't we would leak some memory.
     */
    struct vm_area_struct *entry;
    void *entry_;
    unsigned long index = 0;
    mt_for_each (&addr_space->region_tree, entry_, index, -1UL)
    {
        entry = (struct vm_area_struct *) entry_;
        addr_space_delete(entry);
    }

    paging_free_page_tables(addr_space);
}

/**
 * @brief Fork the current address space into a new address space.
 *
 * @param addr_space The new address space.
 * @return 0 on success, negative on error.
 */
int vm_fork_address_space(struct mm_address_space *addr_space) EXCLUDES(addr_space->vm_lock)
    EXCLUDES(get_current_address_space()->vm_lock)
{
    struct mm_address_space *current_mm = get_current_address_space();
    int err = 0;
    rw_lock_read(&current_mm->vm_lock);

#ifdef CONFIG_DEBUG_ADDRESS_SPACE_ACCT
    mmu_verify_address_space_accounting(get_current_address_space());
#endif

    if (paging_clone_as(addr_space, current_mm) < 0)
    {
        err = -ENOMEM;
        goto out;
    }

    addr_space->resident_set_size = 0;
    addr_space->virtual_memory_size = current_mm->virtual_memory_size;

    struct vm_area_struct *entry;
    void *entry_;
    unsigned long index = 0;
    mt_for_each (&current_mm->region_tree, entry_, index, -1UL)
    {
        entry = (struct vm_area_struct *) entry_;
        if (!fork_vm_area_struct(entry, addr_space))
        {
            tear_down_addr_space(addr_space);
            err = -ENOMEM;
            goto out;
        }
    }

    addr_space->shared_set_size = current_mm->shared_set_size;

    /* We add the old ones here because rss will only be incremented by pages that were newly
     * mapped, since the old page table entries were copied in.
     */
    addr_space->mmap_base = current_mm->mmap_base;
    addr_space->brk = current_mm->brk;
    addr_space->start = current_mm->start;
    addr_space->end = current_mm->end;
    addr_space->arg_start = current_mm->arg_start;
    addr_space->arg_end = current_mm->arg_end;
    memcpy(addr_space->saved_auxv, current_mm->saved_auxv, sizeof(current_mm->saved_auxv));

#ifdef CONFIG_DEBUG_ADDRESS_SPACE_ACCT
    mmu_verify_address_space_accounting(addr_space);
#endif

    rwlock_init(&addr_space->vm_lock);
    validate_mm_tree(addr_space);
out:
    rw_unlock_read(&current_mm->vm_lock);
    return err;
}

/**
 * @brief Changes permissions of a memory area.
 * Note: Deprecated and should not be used.
 * @param range Start of the range.
 * @param pages Number of pages.
 * @param perms New permissions.
 */
void vm_change_perms(void *range, size_t pages, int perms) NO_THREAD_SAFETY_ANALYSIS
{
    struct mm_address_space *as;
    bool kernel = is_higher_half(range);
    DCHECK(!kernel);

    as = &kernel_address_space;
    rw_lock_write(&as->vm_lock);

    for (size_t i = 0; i < pages; i++)
    {
        paging_change_perms(range, perms);

        range = (void *) ((unsigned long) range + PAGE_SIZE);
    }

    vm_invalidate_range((unsigned long) range, pages);
    rw_unlock_write(&as->vm_lock);
}

static bool vma_can_merge_into(struct vm_area_struct *vma, size_t size, int vm_flags,
                               struct file *file, off_t off, bool before)
{
    if (vma->vm_file && file)
    {
        off_t desired_vma_off = vma->vm_offset + (vma->vm_end - vma->vm_start);
        if (!before)
            desired_vma_off = off + size;
        if (off != desired_vma_off)
            return false;
    }

    return vma->vm_flags == vm_flags && vma->vm_file == file;
}

static void vma_post_adjust(struct vm_area_struct *vma)
{
    if (vma->anon_vma)
        spin_unlock(&vma->anon_vma->lock);

    if (vma->vm_obj)
    {
        vm_obj_reassign_mapping(vma->vm_obj, vma);
        spin_unlock(&vma->vm_obj->mapping_lock);
    }
}

static bool can_merge_anon_vmas(struct anon_vma *anon_vma1, struct anon_vma *anon_vma2)
{
    return !anon_vma1 || !anon_vma2 || (anon_vma1 == anon_vma2);
}

static void anon_vma_merge(struct vm_area_struct *vma1, struct vm_area_struct *vma2)
{
    /* vma_pre_merge has been called, anon_vma lock held */
    /* Either one of the vmas does not have an anon_vma, or they're both the same */
    if (!vma1->anon_vma)
    {
        /* Grab the second vma's anon vma, and add ourselves to it */
        vma1->anon_vma = vma2->anon_vma;
        if (vma1->anon_vma)
            __anon_vma_link(vma1->anon_vma, vma1);
    }

    if (vma2->anon_vma)
        __anon_vma_unlink(vma2->anon_vma, vma2);
}

static void vma_pre_merge(struct vm_area_struct *vma1, struct vm_area_struct *vma2)
{
    /* Lock the rmap intances. This stops us from every seeing an inconsistent data structure on
     * rmap's side. */
    struct anon_vma *anon_vma = vma1->anon_vma ? vma1->anon_vma : vma2->anon_vma;
    DCHECK(vma1->vm_obj == vma2->vm_obj);
    if (vma1->vm_obj)
        spin_lock(&vma1->vm_obj->mapping_lock);

    if (anon_vma)
        spin_lock(&anon_vma->lock);
}

static void vma_post_merge(struct vm_area_struct *vma1, struct vm_area_struct *vma2)
{
    /* We don't need to do anything fancy for post-merge, for now, so deal with adjusting prev */
    vma_post_adjust(vma1);
}

static struct vm_area_struct *vma_merge_around(struct vma_iterator *vmi, unsigned int vm_flags,
                                               struct file *file, off_t off)
    REQUIRES(vmi->mm->vm_lock)
{
    struct vm_area_struct *prev, *next, *ret = NULL;
    size_t new_size = vmi->end - vmi->index + 1;

    prev = (struct vm_area_struct *) mas_prev(&vmi->mas, vmi->index - 1);
    next = (struct vm_area_struct *) mas_next(&vmi->mas, vmi->end + 1);

    if (prev && !vma_can_merge_into(prev, new_size, vm_flags, file, off, true))
        prev = NULL;
    if (next && !vma_can_merge_into(next, new_size, vm_flags, file, off, false))
        next = NULL;

    if (prev && next && can_merge_anon_vmas(prev->anon_vma, next->anon_vma))
    {
        /* We can merge with prev *and* next. The whole range (prev->vm_start to next->vm_end) will
         * be covered by a single VMA */
        DCHECK(prev->vm_end == vmi->index && next->vm_start == vmi->end + 1);
        mas_set_range(&vmi->mas, prev->vm_start, next->vm_end - 1);
        if (mas_store_gfp(&vmi->mas, prev, GFP_KERNEL) != 0)
            return NULL;

        vma_pre_merge(prev, next);
        prev->vm_end = next->vm_end;
        if (next->vm_obj)
        {
            /* Remove ourselves from the vm obj */
            vmo_remove_mapping_locked(next->vm_obj, next);
        }

        anon_vma_merge(prev, next);
        vma_post_adjust(prev);
        vma_free(next);
        ret = prev;
    }
    else if (prev)
    {
        /* Merging with prev, quite simple, just nudge vm_end */
        DCHECK(prev->vm_end == vmi->index);
        mas_set_range(&vmi->mas, prev->vm_start, vmi->end);
        if (mas_store_gfp(&vmi->mas, prev, GFP_KERNEL) != 0)
            return NULL;
        vma_pre_adjust(prev);
        prev->vm_end = vmi->end + 1;
        vma_post_adjust(prev);
        ret = prev;
    }
    else if (next)
    {
        /* Merging with next, nudge vm_start and vm_offset if required */
        DCHECK(next->vm_start == vmi->end + 1);
        mas_set_range(&vmi->mas, vmi->index, next->vm_end - 1);
        if (mas_store_gfp(&vmi->mas, next, GFP_KERNEL) != 0)
            return NULL;
        vma_pre_adjust(next);
        if (file)
            next->vm_offset -= (next->vm_start - vmi->index);
        next->vm_start = vmi->index;
        vma_post_adjust(next);
        ret = next;
    }

    if (ret)
    {
        increment_vm_stat(vmi->mm, virtual_memory_size, new_size);
        if (vma_shared(ret))
            increment_vm_stat(vmi->mm, shared_set_size, new_size);
    }
    return ret;
}

static struct vm_area_struct *vma_create(struct vma_iterator *vmi, unsigned int vm_flags,
                                         struct file *file, off_t off)
{
    int err = -ENOMEM;
    size_t size = vmi->end - vmi->index + 1;
    struct vm_area_struct *vma = NULL;
    if (!vm_test_vs_rlimit(vmi->mm, size))
        goto out_error;

    vma = vma_alloc();
    if (!vma)
        goto out_error;
    memset(vma, 0, sizeof(*vma));
    vma->vm_start = vmi->index;
    vma->vm_end = vmi->end + 1;
    vma->vm_flags = vm_flags;
    vma->vm_mm = vmi->mm;

    err = mas_store_gfp(&vmi->mas, vma, GFP_KERNEL);
    if (err)
        goto free_vma;

    if (file)
    {
        vma->vm_offset = off;
        vma->vm_file = file;

        fd_get(file);

        struct inode *ino = file->f_ino;

        if (S_ISCHR(ino->i_mode))
        {
            if (!file->f_op->mmap)
            {
                err = -ENODEV;
                goto unmap_vma;
            }

            void *ret = file->f_op->mmap(vma, file);
            if (!ret)
            {
                err = -errno;
                goto unmap_vma;
            }

            inode_update_atime(ino);
            goto out;
        }
    }

    if (vma_setup_backing(vma, size >> PAGE_SHIFT, file != NULL) < 0)
        goto unmap_vma;

out:
    increment_vm_stat(vmi->mm, virtual_memory_size, size);
    if (vma_shared(vma))
        increment_vm_stat(vmi->mm, shared_set_size, size);

    return vma;
unmap_vma:
    if (file)
        fd_put(file);
    CHECK(mas_erase(&vmi->mas) == vma);
free_vma:
    vma_free(vma);
out_error:
    return ERR_PTR(err);
}

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
void *vm_mmap(void *addr, size_t length, int prot, int flags, struct file *file, off_t off)
{
    struct vm_area_struct *vma = NULL;
    unsigned long virt = (unsigned long) addr;
    u64 extra_flags = 0;

    struct mm_address_space *mm = get_current_address_space();

    /* We don't like this offset. */
    if (off & (PAGE_SIZE - 1))
        return ERR_PTR(-EINVAL);

    /* Calculate the pages needed for the overall size */
    size_t pages = vm_size_to_pages(length);

    if (prot & (PROT_WRITE | PROT_EXEC))
        prot |= PROT_READ;

    int vm_prot = VM_USER | ((prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) ? VM_READ : 0) |
                  ((prot & PROT_WRITE) ? VM_WRITE : 0) | ((prot & PROT_EXEC) ? VM_EXEC : 0);

    if (flags & MAP_SHARED)
        vm_prot |= VM_SHARED;

    /* Sanitize the address and length */
    const unsigned long aligned_len = pages << PAGE_SHIFT;

    rw_lock_write(&mm->vm_lock);
    if (aligned_len > arch_low_half_max)
        goto enomem;

    if (is_higher_half(addr) || virt & (PAGE_SIZE - 1) || virt > arch_low_half_max - aligned_len ||
        virt + aligned_len < arch_low_half_min)
    {
        if (flags & MAP_FIXED)
            goto enomem;
        else
        {
            addr = NULL;
            virt = 0;
        }
    }

    VMA_ITERATOR(vmi, mm, virt, virt + aligned_len);

    extra_flags = arch_vm_interpret_mmap_hint_flags(addr, flags);

    if (virt)
    {
        if (flags & MAP_FIXED)
            __vm_munmap(mm, addr, pages << PAGE_SHIFT);
    }
    else
    {
        if (vm_alloc_address(&vmi, VM_ADDRESS_USER | extra_flags, aligned_len, VM_TYPE_REGULAR) < 0)
            goto enomem;
        virt = vmi.index;
    }

    if (!vm_test_vs_rlimit(mm, vmi.end - vmi.index + 1))
        goto enomem;

    vma = vma_merge_around(&vmi, vm_prot, file, off);
    if (vma)
        goto out_vmi;

    /* vma_merge_around may touch around the vmi, reset the state */
    mas_set_range(&vmi.mas, vmi.index, vmi.end);

    if (flags & MAP_ANONYMOUS)
        file = NULL;

    vma = vma_create(&vmi, vm_prot, file, off);
    if (IS_ERR(vma))
        virt = (unsigned long) vma;

out_vmi:
    vmi_destroy(&vmi);
out:
    validate_mm_tree(mm);
    rw_unlock_write(&mm->vm_lock);
    return (void *) virt;
enomem:
    virt = -ENOMEM;
    goto out;
}

void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t off)
{
    int error = 0;

    struct file *file = NULL;
    void *ret = NULL;
    bool is_file_mapping = !(flags & MAP_ANONYMOUS);

    /* Ok, start the basic input sanitation for user-space inputs */
    if (length == 0)
        return (void *) -EINVAL;

    if (!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
        return (void *) -EINVAL;

    if (flags & MAP_PRIVATE && flags & MAP_SHARED)
        return (void *) -EINVAL;

    /* Our mmap() implementation needs page aligned offsets */
    if (off % PAGE_SIZE)
        return (void *) -EINVAL;

    if (is_file_mapping) /* This is a file-backed mapping */
    {
        file = get_file_description(fd);
        if (!file)
            return (void *) (unsigned long) -errno;

        /* You can't map a file without having read access to it. */
        if (!fd_may_access(file, FILE_ACCESS_READ))
        {
            error = -EACCES;
            goto out_error;
        }

        bool fd_has_write = fd_may_access(file, FILE_ACCESS_WRITE);

        /* You can't create a shared mapping of a file without having write access to it */
        if (!fd_has_write && prot & PROT_WRITE && flags & MAP_SHARED)
        {
            error = -EACCES;
            goto out_error;
        }
    }

    ret = vm_mmap(addr, length, prot, flags, file, off);
    if (file)
        fd_put(file);

    return ret;
out_error:
    if (file)
        fd_put(file);
    return (void *) (unsigned long) error;
}

int sys_munmap(void *addr, size_t length)
{
    if (is_higher_half(addr))
        return -EINVAL;

    size_t pages = vm_size_to_pages(length);

    if ((unsigned long) addr & (PAGE_SIZE - 1))
        return -EINVAL;

    struct mm_address_space *mm = get_current_address_space();
    int ret = vm_munmap(mm, addr, pages << PAGE_SHIFT);
    return ret;
}

static void vm_copy_region(const struct vm_area_struct *source, struct vm_area_struct *dest)
{
    dest->vm_file = source->vm_file;
    if (dest->vm_file)
        fd_get(dest->vm_file);

    dest->vm_flags = source->vm_flags;
    dest->vm_offset = source->vm_offset;
    dest->vm_mm = source->vm_mm;
    dest->vm_obj = source->vm_obj;
    if (dest->vm_obj)
        vmo_ref(dest->vm_obj);
    dest->anon_vma = source->anon_vma;
    dest->vm_ops = source->vm_ops;
}

static void vma_pre_adjust(struct vm_area_struct *vma)
{
    /* Lock the rmap intances. This stops us from every seeing an inconsistent data structure on
     * rmap's side. */
    if (vma->vm_obj)
        spin_lock(&vma->vm_obj->mapping_lock);

    if (vma->anon_vma)
        spin_lock(&vma->anon_vma->lock);
}

static void vma_post_split(struct vm_area_struct *vma, struct vm_area_struct *new_vma)
{
    /* Correct the rmaps post-split, and unlock. */
    if (vma->anon_vma)
    {
        __anon_vma_link(vma->anon_vma, new_vma);
        spin_unlock(&vma->anon_vma->lock);
    }

    if (vma->vm_obj)
    {
        DCHECK(vma->vm_obj == new_vma->vm_obj);
        vm_obj_reassign_mapping(vma->vm_obj, vma);
        vmo_assign_mapping_locked(vma->vm_obj, new_vma);
        spin_unlock(&vma->vm_obj->mapping_lock);
    }
}

static struct vm_area_struct *vm_split_region(struct mm_address_space *as,
                                              struct vm_area_struct *vma, unsigned long addr,
                                              bool below, struct vma_iterator *vmi)
    REQUIRES(as->vm_lock)
{
    DCHECK((addr & (PAGE_SIZE - 1)) == 0);
    size_t region_off = addr - vma->vm_start;
    struct vm_area_struct *newr = vma_alloc();
    if (!newr)
        return NULL;

    /* Reset the mas range to the new sub-region */
    __mas_set_range(&vmi->mas, below ? vma->vm_start : addr, (below ? addr : vma->vm_end) - 1);
    if (mas_preallocate(&vmi->mas, newr, GFP_KERNEL) == -ENOMEM)
    {
        vma_free(newr);
        return NULL;
    }

    memset(newr, 0, sizeof(*newr));
    vm_copy_region(vma, newr);

    DCHECK(vma->vm_end > addr);

    vma_pre_adjust(vma);

    if (below)
    {
        newr->vm_start = vma->vm_start;
        newr->vm_end = addr;
        vma->vm_start = addr;
        vma->vm_offset += region_off;
    }
    else
    {
        newr->vm_start = addr;
        newr->vm_end = vma->vm_end;
        newr->vm_offset += region_off;
        vma->vm_end = addr;
    }

    vma_post_split(vma, newr);

    mas_store_prealloc(&vmi->mas, newr);
    DCHECK(vmi->mas.index == newr->vm_start);
    // validate_mm_tree(as);
    return newr;
}

static void vm_mprotect_handle_prot(struct vm_area_struct *region, int *pprot)
{
    int prot = *pprot;
    bool marking_write = (prot & VM_WRITE) && !(region->vm_flags & VM_WRITE);

    region->vm_flags = prot;

    if (marking_write && (vm_mapping_is_cow(region) || vm_mapping_requires_write_protect(region)))
    {
        /* If we're a COW mapping or some kind of mapping that requires write-protection,
         * we can't change the pages' permissions to allow VM_WRITE
         */
        *pprot &= ~VM_WRITE;
    }
}

#if !defined(CONFIG_X86) && !defined(CONFIG_RISCV)
/* TODO: Remove once all architectures have been moved to the new shared page table code */
void vm_do_mmu_mprotect(struct mm_address_space *as, void *address, size_t nr_pgs, int old_prots,
                        int new_prots)
{
    void *addr = address;

    for (size_t i = 0; i < nr_pgs; i++)
    {
        vm_mmu_mprotect_page(as, address, old_prots, new_prots);

        address = (void *) ((unsigned long) address + PAGE_SIZE);
    }

    vm_invalidate_range((unsigned long) addr, nr_pgs);
}
#endif

struct vm_area_struct *vma_prepare_modify(struct vma_iterator *vmi, struct vm_area_struct *vma,
                                          unsigned long start, unsigned long end)
    REQUIRES(vmi->mm->vm_lock)
{
    if (start > vma->vm_start)
    {
        vma = vm_split_region(vmi->mm, vma, start, false, vmi);
        if (!vma)
            return NULL;
    }

    if (end < vma->vm_end)
        vma = vm_split_region(vmi->mm, vma, end, true, vmi);
    return vma;
}

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
int vm_mprotect(struct mm_address_space *as, void *__addr, size_t size, int prot)
    EXCLUDES(as->vm_lock)
{
    int err = -ENOMEM;
    unsigned long addr = (unsigned long) __addr;
    unsigned long limit = addr + size;
    VMA_ITERATOR(vmi, as, addr, limit);

    rw_lock_write(&as->vm_lock);

    /* Note: vm_munmap has some vma detaching logic for the simple fact that POSIX does not
     * allow for a partial unmap in case of an error. Whereas this is not the case for mprotect.
     */

    struct vm_area_struct *vma = vm_search(as, (void *) addr, PAGE_SIZE);
    if (!vma)
        goto out;

    mas_for_each(&vmi.mas, vma, vmi.end)
    {
        if (vma->vm_start >= limit)
            break;
        vma = vma_prepare_modify(&vmi, vma, addr, limit);
        if (!vma)
            goto out;
        DCHECK(vma->vm_start >= addr && vma->vm_end <= limit);
        if (vma_shared(vma) && vma->vm_file && prot & PROT_WRITE)
        {
            /* Block the mapping if we're trying to mprotect a shared mapping to PROT_WRITE while
             * not having the necessary perms on the file.
             */

            struct file *file = vma->vm_file;
            bool fd_has_write = fd_may_access(file, FILE_ACCESS_WRITE);

            if (!fd_has_write)
            {
                err = -EACCES;
                goto out;
            }
        }

        int old_prots = vma->vm_flags;
        int new_prots = prot;
        vm_mprotect_handle_prot(vma, &new_prots);
        vm_do_mmu_mprotect(as, (void *) vma->vm_start, (vma->vm_end - vma->vm_start) >> PAGE_SHIFT,
                           old_prots, new_prots);
        if (vma->vm_end == limit)
            break;
    }

    err = 0;

out:
    vmi_destroy(&vmi);
    validate_mm_tree(as);
    rw_unlock_write(&as->vm_lock);
    return err;
}

int sys_mprotect(void *addr, size_t len, int prot)
{
    if (is_higher_half(addr))
        return -EINVAL;

    /* The address needs to be page aligned */
    if ((unsigned long) addr & (PAGE_SIZE - 1))
        return -EINVAL;

    /* Error on len misalignment */
    if (len & (PAGE_SIZE - 1))
        return -EINVAL;

    int vm_prot = VM_USER | ((prot & PROT_WRITE) ? VM_WRITE : 0) |
                  ((prot & PROT_EXEC) ? VM_EXEC : 0) | ((prot & PROT_READ) ? VM_READ : 0);

    if (prot & PROT_WRITE)
        vm_prot |= VM_READ;

    size_t pages = vm_size_to_pages(len);

    len = pages << PAGE_SHIFT; /* Align len on a page boundary */

    return vm_mprotect(get_current_address_space(), addr, len, vm_prot);
}

static int vm_expand_brk(struct mm_address_space *as, size_t nr_pages) REQUIRES(as->vm_lock);

__always_inline int do_inc_brk(struct mm_address_space *as, void *oldbrk, void *newbrk)
    REQUIRES(as->vm_lock)
{
    void *oldpage = page_align_up(oldbrk);
    void *newpage = page_align_up(newbrk);

    size_t pages = ((uintptr_t) newpage - (uintptr_t) oldpage) / PAGE_SIZE;

    if (pages > 0)
        return vm_expand_brk(as, pages);
    return 0;
}

uint64_t sys_brk(void *newbrk)
{
    unsigned long ret;
    struct mm_address_space *as = get_current_address_space();

    rw_lock_write(&as->vm_lock);

    if (newbrk == NULL)
    {
        ret = (unsigned long) as->brk;
        goto out;
    }

    void *old_brk = as->brk;
    ptrdiff_t diff = (ptrdiff_t) newbrk - (ptrdiff_t) old_brk;

    if (diff < 0)
    {
        /* TODO: Implement freeing memory with brk(2) */
        as->brk = newbrk;
    }
    else
    {
        /* Increment the program brk */
        if (do_inc_brk(as, old_brk, newbrk) < 0)
        {
            ret = -ENOMEM;
            goto out;
        }

        as->brk = newbrk;
    }

    ret = (unsigned long) as->brk;
out:
    rw_unlock_write(&as->vm_lock);
    return ret;
}

static bool vm_print(struct vm_area_struct *region)
{
    bool x = region->vm_flags & VM_EXEC;
    bool w = region->vm_flags & VM_WRITE;
    bool file_backed = is_file_backed(region);
    struct file *fd = region->vm_file;

    printk("[%016lx - %016lx] : %s%s%s ", region->vm_start, region->vm_end, "R", w ? "W" : "-",
           x ? "X" : "-");
    printk("vmo %p mapped at offset %lx", region->vm_obj, region->vm_offset);
    if (file_backed)
        printk(" - file backed ino %lu\n", fd->f_ino->i_inode);
    else
        printk("\n");

    return true;
}

/**
 * @brief Traverses the current process's memory map and prints information.
 *
 */
void vm_print_umap()
{
    // vm_for_every_region(*get_current_address_space(), vm_print);
    printk("brk: %p\n", get_current_address_space()->brk);
}

#define DEBUG_PRINT_MAPPING 0

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
                           size_t flags)
{
    if (flags & VM_WRITE)
        assert((unsigned long) phys != (unsigned long) page_to_phys(vm_zero_page));

    size_t pages = vm_size_to_pages(size);

#if DEBUG_PRINT_MAPPING
    printk("__map_pages_to_vaddr: %p (phys %p) - %lx\n", virt, phys, (unsigned long) virt + size);
#endif
    void *ptr = virt;
    for (uintptr_t virt = (uintptr_t) ptr, _phys = (uintptr_t) phys, i = 0; i < pages;
         virt += PAGE_SIZE, _phys += PAGE_SIZE, ++i)
    {
        if (!vm_map_page(as, virt, _phys, flags, NULL))
            return NULL;
    }

    if (!(flags & VM_NOFLUSH))
        vm_invalidate_range((unsigned long) virt, pages);

    return ptr;
}

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
void *map_pages_to_vaddr(void *virt, void *phys, size_t size, size_t flags)
{
    return __map_pages_to_vaddr(&kernel_address_space, virt, phys, size, flags);
}

static int vm_pf_get_page_from_vmo(struct vm_pf_context *ctx)
{
    struct vm_area_struct *entry = ctx->entry;
    struct inode *ino = entry->vm_file->f_ino;
    size_t vmo_off = (ctx->vpage - entry->vm_start) + entry->vm_offset;
    DCHECK(entry->vm_file != NULL);

    /* SIGBUS! */
    if (vmo_off >= ino->i_size)
        return -ENOENT;

    return filemap_find_page(ino, vmo_off >> PAGE_SHIFT, 0, &ctx->page,
                             &entry->vm_file->f_ra_state);
}

static int find_page_err_to_signal(int st)
{
    if (unlikely(st == 0))
        return 0;

    switch (st)
    {
        case -ENOENT:
        case -EIO:
            return VM_SIGBUS;
        case -ENOMEM:
        default:
            return VM_SIGSEGV;
    }
}

static bool vm_mapping_is_cow(struct vm_area_struct *entry)
{
    return vma_private(entry);
}

static bool vm_fault_was_spurious(struct fault_info *info, struct vm_pf_context *pf)
{
    if (!(pf->mapping_info & PAGE_PRESENT))
        return false;
    if (info->write && !(pf->mapping_info & PAGE_WRITABLE))
        return false;
    if (info->exec && !(pf->mapping_info & PAGE_EXECUTABLE))
        return false;
    return true;
}

static int __vm_handle_pf(struct vm_area_struct *entry, struct fault_info *info)
{
#if 0
    const pid_t pid = get_current_process()->pid_;
    const u64 addr = info->fault_address;
    const u8 fault_read = info->read;
    const u8 fault_exec = info->exec;
    TRACE_EVENT_DURATION(vm_page_fault, addr, pid, fault_read, fault_write, fault_exec);
#endif
    const u8 fault_write = info->write;
    struct vm_pf_context context;
    context.entry = entry;
    context.info = info;
    context.vpage = info->fault_address & -PAGE_SIZE;
    context.page = NULL;
    context.page_rwx = entry->vm_flags;
    context.oldpte = pte_get(entry->vm_mm, context.vpage);
    context.mapping_info = get_mapping_info((void *) context.vpage);

    if (!pte_none(context.oldpte) && (!pte_present(context.oldpte) || pte_protnone(context.oldpte)))
        return do_swap_page(&context);

    if (pte_present(context.oldpte) && !pte_write(context.oldpte) && fault_write &&
        vma_private(entry))
        return do_wp_page(&context);

    /* If spurious, invalidate the TLB _locally_ and retry */
    if (vm_fault_was_spurious(info, &context))
    {
        tlbi_handle_spurious_fault_pte(entry->vm_mm, context.vpage);
        return 0;
    }

    if (entry->vm_ops && entry->vm_ops->fault)
        return entry->vm_ops->fault(&context);

    /* This is unreachable */
    CHECK(0);
    return 0;
}

/**
 * @brief Handles a page fault.
 *
 * @param info A pointer to a fault_info structure.
 * @return 0 on success or negative error codes.
 */
int vm_handle_page_fault(struct fault_info *info)
{
    bool use_kernel_as = !info->user && is_higher_half((void *) info->fault_address);
    struct mm_address_space *as =
        use_kernel_as ? &kernel_address_space : get_current_address_space();

    if (get_current_thread()->pagefault_disabled)
    {
        info->signal = VM_SIGSEGV;
        return -1;
    }

    if (sched_is_preemption_disabled())
        panic("Page fault while preemption was disabled\n");
    if (irq_is_disabled())
        panic("Page fault while IRQs were disabled\n");

    /* Surrender immediately if there's no user address space */
    if (!as)
    {
        info->signal = VM_SIGSEGV;
        return -1;
    }

    rw_lock_read(&as->vm_lock);

    struct vm_area_struct *entry = vm_find_region(as, (void *) info->fault_address);
    if (!entry)
    {
        struct thread *ct = get_current_thread();
        if (ct && info->user)
        {
            printk("Curr thread: %p\n", ct);
            const char *str;
            if (info->write)
                str = "write";
            else if (info->exec)
                str = "exec";
            else
                str = "read";
            printk("Page fault at %lx, %s, ip %lx, process name %s\n", info->fault_address, str,
                   info->ip, current ? current->comm : "(kernel)");
#if 0
            vm_print_umap();
            panic("pid %ld page fault", current->pid_);
#endif
        }

        info->signal = VM_SIGSEGV;
        goto err;
    }

    info->error_info = VM_BAD_PERMISSIONS;

    if (info->write && !(entry->vm_flags & VM_WRITE))
        goto err;
    if (info->exec && !(entry->vm_flags & VM_EXEC))
        goto err;
    if (info->user && !(entry->vm_flags & VM_USER))
        goto err;
    if (info->read && !(entry->vm_flags & VM_READ))
        goto err;

    info->error_info = 0;
    __sync_add_and_fetch(&as->page_faults, 1);
    int ret = __vm_handle_pf(entry, info);
    if (ret >= 0)
    {
        if (ret & VM_FAULT_MAJOR)
            current->majflt++;
        else
            current->minflt++;
    }

    rw_unlock_read(&as->vm_lock);
    return ret;
err:
    rw_unlock_read(&as->vm_lock);
    return -1;
}

static void vm_destroy_area(struct vm_area_struct *region)
{
    vm_mmu_unmap(region->vm_mm, (void *) region->vm_start, vma_pages(region), region);

    decrement_vm_stat(region->vm_mm, virtual_memory_size, region->vm_end - region->vm_start);

    if (vma_shared(region))
        decrement_vm_stat(region->vm_mm, shared_set_size, region->vm_end - region->vm_start);

    vma_destroy(region);
}

/**
 * @brief Destroys an address space.
 *
 * @param mm A pointer to a valid mm_address_space.
 */
void vm_destroy_addr_space(struct mm_address_space *mm)
{
    /* First, iterate through the maple tree and free/unmap stuff */
    rw_lock_write(&mm->vm_lock);

    struct vm_area_struct *entry;
    unsigned long index = 0;
    mt_for_each (&mm->region_tree, entry, index, -1UL)
        vm_destroy_area(entry);

    mtree_destroy(&mm->region_tree);
    assert(mm->resident_set_size == 0);
    assert(mm->shared_set_size == 0);
    if (WARN_ON(mm->virtual_memory_size > 0))
    {
        pr_warn("mm: Bad VSZ accounting %lx (%ld)\n", mm->virtual_memory_size,
                mm->virtual_memory_size);
    }

    assert(mm->page_tables_size == PAGE_SIZE);

    rw_unlock_write(&mm->vm_lock);
}

/**
 * @brief Loads the fallback paging tables.
 *
 */
void vm_switch_to_fallback_pgd()
{
    assert(sched_is_preemption_disabled() == true);

    vm_load_arch_mmu(&kernel_address_space.arch_mmu);
}

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
int vm_sanitize_address(void *address, size_t pages)
{
    if (is_higher_half(address))
        return -1;
    if (is_invalid_arch_range(address, pages) < 0)
        return -1;
    return 0;
}

/**
 * @brief Generates a new mmap base, taking into account arch-dependent addresses and possibly
 * KASLR.
 *
 * @return The new mmap base. Note: This is not a valid pointer, but the starting point
 *         for mmap allocations.
 */
void *vm_gen_mmap_base()
{
    uintptr_t mmap_base = arch_mmap_base;
#ifdef CONFIG_ASLR
    if (enable_aslr)
    {
        mmap_base = vm_randomize_address(mmap_base, MMAP_ASLR_BITS);

        return (void *) mmap_base;
    }
#endif
    return (void *) mmap_base;
}

/**
 * @brief Generates a new brk base, taking into account arch-dependent addresses and possibly KASLR.
 *
 * @return The new brk base. Note: This is not a valid pointer, but the starting point
 *         for brk allocations.
 */
void *vm_gen_brk_base()
{
    uintptr_t brk_base = arch_brk_base;
#ifdef CONFIG_ASLR
    if (enable_aslr)
    {
        brk_base = vm_randomize_address(arch_brk_base, BRK_ASLR_BITS);
        return (void *) brk_base;
    }
#endif
    return (void *) brk_base;
}

int sys_memstat(struct memstat *memstat)
{
    struct memstat buf;
    page_get_stats(&buf);

    if (copy_to_user(memstat, &buf, sizeof(buf)) < 0)
        return -EFAULT;
    return 0;
}

/* Reads from vm_aslr - reads enable_aslr */
ssize_t aslr_read(void *buffer, size_t size, off_t off)
{
    UNUSED(size);
    UNUSED(off);
    char *buf = (char *) buffer;
    if (off == 1)
        return 0;

    if (enable_aslr)
    {
        *buf = '1';
    }
    else
        *buf = '0';
    return 1;
}

/* Writes to vm_aslr - modifies enable_aslr */
ssize_t aslr_write(void *buffer, size_t size, off_t off)
{
    UNUSED(size);
    UNUSED(off);
    char *buf = (char *) buffer;
    if (*buf == '1')
    {
        enable_aslr = true;
    }
    else if (*buf == '0')
    {
        enable_aslr = false;
    }

    return 1;
}

ssize_t vm_traverse_kmaps(void *node, char *address, size_t *size, off_t off)
{
    UNUSED(node);
    UNUSED(size);
    UNUSED(off);
    /* First write the lowest addresses, then the middle address, and then the higher addresses
     */
    strcpy(address, "unimplemented\n");
    return strlen(address);
}

ssize_t kmaps_read(void *buffer, size_t size, off_t off)
{
    UNUSED(off);
    return 0;
#if 0
	return vm_traverse_kmaps(kernel_tree, buffer, &size, 0);
#endif
}

ssize_t evict_write(void *buf, size_t size, off_t off)
{
    if (size == 0)
        return 0;
    char c;

    if (copy_from_user(&c, buf, 1) < 0)
        return -EFAULT;

#if 0
    if (c == '2' || c == '3')
        dentry_trim_caches();
#endif

    if (c == '1' || c == '3')
        inode_trim_cache();

    return size;
}

static struct sysfs_object vm_obj;
static struct sysfs_object aslr_control;
static struct sysfs_object kmaps;
static struct sysfs_object evict_obj;

/**
 * @brief Initialises sysfs nodes for the vm subsystem.
 *
 */
void vm_sysfs_init(void)
{
    INFO("vmm", "Setting up /sys/vm\n");

    assert(sysfs_object_init("vm", &vm_obj) == 0);
    vm_obj.perms = 0755 | S_IFDIR;

    assert(sysfs_init_and_add("aslr_ctl", &aslr_control, &vm_obj) == 0);
    aslr_control.read = aslr_read;
    aslr_control.write = aslr_write;
    aslr_control.perms = 0644 | S_IFREG;

    assert(sysfs_init_and_add("kmaps", &kmaps, &vm_obj) == 0);
    kmaps.read = kmaps_read;
    kmaps.perms = 0444 | S_IFREG;

    assert(sysfs_init_and_add("evict", &evict_obj, &vm_obj) == 0);
    evict_obj.write = evict_write;
    evict_obj.perms = 0644 | S_IFREG;

    sysfs_add(&vm_obj, NULL);
}

char *strcpy_from_user(const char *uptr)
{
    ssize_t len = strlen_user(uptr);
    if (len < 0)
    {
        errno = EFAULT;
        return NULL;
    }

    char *buf = (char *) malloc(len + 1);
    if (!buf)
        return NULL;
    buf[len] = '\0';

    if (copy_from_user(buf, uptr, len) < 0)
    {
        free(buf);
        errno = EFAULT;
        return NULL;
    }

    return buf;
}

/**
 * @brief Updates the memory map's ranges.
 * Used in arch dependent early boot procedures when architectures
 * have variable address space sizes. See example uses of this
 * function in arch/x86_64.
 *
 * @param new_kernel_space_base The new virtual memory base.
 */
void vm_update_addresses(uintptr_t new_kernel_space_base)
{
    vmalloc_space += new_kernel_space_base;
    high_half = new_kernel_space_base;
}

/**
 * @brief Generate a ASLR'd address.
 * Takes into account base and bits.
 *
 * @param base The base address.
 * @param bits The number of bits that can be randomised.
 * @return The randomised address.
 */
uintptr_t vm_randomize_address(uintptr_t base, uintptr_t bits)
{
#ifdef CONFIG_KASLR
    if (bits != 0)
        bits--;
    uintptr_t mask = UINTPTR_MAX & ~(-(1UL << bits));
    /* Get entropy from arc4random() */
    uintptr_t result = ((uintptr_t) arc4random() << 12) & mask;
    result |= ((uintptr_t) arc4random() << 44) & mask;

    base |= result;
#endif
    return base;
}

/**
 * @brief Does the fatal page fault procedure.
 * When a user fault, kills the process; else, panics.
 *
 * @param info A pointer to a fault_info structure.
 */
void vm_do_fatal_page_fault(struct fault_info *info)
{
    bool is_user_mode = info->user;

    if (is_user_mode)
    {
        printf("%s at %016lx at ip %lx in process %u(%s)\n",
               info->signal == SIGSEGV ? "SEGV" : "SIGBUS", info->fault_address, info->ip,
               current->pid_, current->comm);
        printf("Error info: %x on %c%c%c\n", info->error_info, info->read ? 'r' : '-',
               info->write ? 'w' : '-', info->exec ? 'x' : '-');
        printf("Program base: %p\n", current->interp_base);

        siginfo_t sinfo = {};

        if (info->signal == SIGSEGV)
        {
            sinfo.si_code = info->error_info & VM_BAD_PERMISSIONS ? SEGV_ACCERR : SEGV_MAPERR;
        }
        else if (info->signal == SIGBUS)
        {
            // TODO: Add si_codes for sigbus
            sinfo.si_code = SI_KERNEL;
        }

        sinfo.si_addr = (void *) info->fault_address;
        raise_sig_curthr(info->signal, SIGNAL_FORCE, &sinfo);
    }
    else
    {
        panic("Kernel fatal segfault accessing %016lx at ip %lx\n", info->fault_address, info->ip);
    }
}

/**
 * @brief Sets up backing for a newly-mmaped region.
 *
 * @param region A pointer to a vm_area_struct.
 * @param pages The size of the region, in pages.
 * @param is_file_backed True if file backed.
 * @return 0 on success, negative for errors.
 */
int vma_setup_backing(struct vm_area_struct *region, size_t pages, bool is_file_backed)
{
    bool is_shared = vma_shared(region);

    if (!is_file_backed && is_shared)
    {
        region->vm_file = anon_get_shmem(pages << PAGE_SHIFT);
        if (!region->vm_file)
            return -ENOMEM;
        is_file_backed = true;
    }

    struct vm_object *vmo;

    if (is_file_backed)
    {
        vmo = region->vm_file->f_mapping;
        CHECK(vmo != NULL);
        vmo_ref(vmo);
        region->vm_ops = &file_vmops;
    }
    else
    {
        /* Anonymous, private memory uses amaps now */
        vmo = NULL;
        region->vm_ops = &anon_vmops;
    }

    if (vmo)
    {
        vmo_assign_mapping(vmo, region);
        assert(region->vm_obj == NULL);
        region->vm_obj = vmo;
    }

    return 0;
}

/**
 * @brief Determines if a mapping is file backed.
 *
 * @param region A pointer to the vm_area_struct.
 * @return True if file backed, false if not.
 */
bool is_file_backed(struct vm_area_struct *region)
{
    return region->vm_file != NULL;
}

/**
 * @brief Allocates a new mapping and maps a list of pages.
 *
 * @param pl The list of pages.
 * @param size The size of the mapping, in bytes.
 * @param prot The desired protection flags.
 * @return A pointer to the new mapping, or NULL if it failed.
 */
void *map_page_list(struct page *pl, size_t size, uint64_t prot)
    EXCLUDES(kernel_address_space.vm_lock)
{
    return NULL;
}

/**
 * @brief Sets up a new address space on \p mm
 *
 * @param mm A pointer to the new address space.
 * @return 0 on success, negative error codes.
 */
int vm_create_address_space(struct mm_address_space *mm)
{
    mm->mmap_base = vm_gen_mmap_base();
    mm->start = arch_low_half_min;
    mm->end = arch_low_half_max;
    mm->resident_set_size = 0;
    mm->shared_set_size = 0;
    mm->virtual_memory_size = 0;

    // assert(mm->active_mask.is_empty() == true);

    rwlock_init(&mm->vm_lock);
    return 0;
}

/**
 * @brief Sets up the brk region for a new process.
 *
 * @param mm The target address space.
 * @return 0 on success, or negative error codes.
 */
int vm_create_brk(struct mm_address_space *mm)
{
    mm->brk = vm_mmap(vm_gen_brk_base(), 1 << PAGE_SHIFT, PROT_WRITE,
                      MAP_PRIVATE | MAP_FIXED | MAP_ANON, NULL, 0);

    if (IS_ERR(mm->brk))
        return PTR_ERR(mm->brk);

    return 0;
}

/**
 * @brief Retrieves the fallback paging directories.
 * The kernel has a fallback pgd on which process fall back to right before freeing
 * its own pgd, during process destruction.
 *
 * @return void* The fallback pgd.
 */
void *vm_get_fallback_pgd()
{
    return vm_get_pgd(&kernel_address_space.arch_mmu);
}

void vm_remove_region(struct mm_address_space *as, struct vm_area_struct *region)
    REQUIRES(as->vm_lock)
{
    void *ret = mtree_erase(&as->region_tree, region->vm_start);
    CHECK(ret == region);
}

int __vm_munmap(struct mm_address_space *as, void *__addr, size_t size) REQUIRES(as->vm_lock)
{
    unsigned long addr = (unsigned long) __addr & -PAGE_SIZE;
    unsigned long limit = ALIGN_TO(((unsigned long) __addr) + size, PAGE_SIZE);
    struct list_head list = LIST_HEAD_INIT(list);

    struct vm_area_struct *vma = vm_search(as, (void *) addr, PAGE_SIZE);
    if (!vma)
        return -EINVAL;

    /* Gather munmap regions into our local list. No permanent changes are done in this loop,
     * while regions are live *except unlinking from the BST*.
     */

    VMA_ITERATOR(vmi, as, addr, limit);

    mas_for_each(&vmi.mas, vma, vmi.end)
    {
        if (vma->vm_start >= limit)
            break;
        vma = vma_prepare_modify(&vmi, vma, addr, limit);
        if (!vma)
            goto restore;

        DCHECK(vma->vm_start >= addr && vma->vm_end <= limit);
        DCHECK(vmi.mas.index == vma->vm_start && vmi.mas.last == vma->vm_end - 1);
        CHECK(mas_erase(&vmi.mas) == vma);
        list_add_tail(&vma->vm_detached_node, &list);
        if (limit == vma->vm_end)
            break;
    }

    list_for_every_safe (&list)
    {
        vma = container_of(l, struct vm_area_struct, vm_detached_node);
        DCHECK(vma->vm_start >= addr && vma->vm_end <= limit);
        bool is_shared = vma_shared(vma);
        unsigned long sz = vma->vm_end - vma->vm_start;

        vm_mmu_unmap(as, (void *) vma->vm_start, vma_pages(vma), vma);
        list_remove(&vma->vm_detached_node);
        vma_destroy(vma);

        decrement_vm_stat(as, virtual_memory_size, sz);
        if (is_shared)
            decrement_vm_stat(as, shared_set_size, sz);
    }

    vmi_destroy(&vmi);
    validate_mm_tree(as);
    return 0;
restore:
    /* Something back there just failed, restore the old regions and -ENOMEM */
    list_for_every_safe (&list)
    {
        vma = container_of(l, struct vm_area_struct, vm_detached_node);
        list_remove(&vma->vm_detached_node);
        vm_insert_region(as, vma);
    }

    vmi_destroy(&vmi);
    validate_mm_tree(as);
    return -ENOMEM;
}

/**
 * @brief Unmaps a memory range.
 *
 * @param as The target address space.
 * @param __addr The start of the memory range.
 * @param size The size of the memory range, in bytes.
 * @return 0 on success, or negative error codes.
 */
int vm_munmap(struct mm_address_space *as, void *__addr, size_t size)
{
    unsigned long addr = (unsigned long) __addr;
    if (addr < as->start || addr > as->end)
        return -EINVAL;
    if (size == 0)
        return -EINVAL;
    if (addr & (PAGE_SIZE - 1))
        return -EINVAL;

    rw_lock_write(&as->vm_lock);
    int err = __vm_munmap(as, __addr, size);
    rw_unlock_write(&as->vm_lock);
    return err;
}

#if CONFIG_TRACK_TLB_DELTA
hrtime_delta_t last_inval_delta = 0;
#endif

/**
 * @brief Invalidates a range of memory in the current address space.
 * This function handles TLB shootdowns on its own.
 *
 * @param addr The start of the range.
 * @param pages The size of the range, in pages.
 */
void vm_invalidate_range(unsigned long addr, size_t pages)
{
    return mmu_invalidate_range(addr, pages, get_current_address_space());
}

static bool vm_can_expand(struct mm_address_space *as, struct vm_area_struct *region,
                          size_t new_size)
{
    /* Can always shrink the mapping */
    if (new_size < region->vm_end - region->vm_start)
        return true;

    unsigned long index = region->vm_end;
    void *ret = mt_find_after(&as->region_tree, &index, as->end);

    // If there's no region after this one, we're clear to expand
    // TODO: What if we overflow here?
    if (!ret)
        return true;
    struct vm_area_struct *next = (struct vm_area_struct *) ret;

    /* Calculate the hole size, and if >= new_size, we're good */
    size_t hole_size = next->vm_start - region->vm_start;

    return hole_size >= new_size;
}

static int __vm_expand_mapping(struct vm_area_struct *region, size_t new_size)
{
    size_t diff = new_size - (region->vm_end - region->vm_start);
    if (!vm_test_vs_rlimit(region->vm_mm, new_size))
        return -ENOMEM;

    region->vm_end += diff;
    increment_vm_stat(region->vm_mm, virtual_memory_size, diff);
    if (vma_shared(region))
        increment_vm_stat(region->vm_mm, shared_set_size, diff);

    int st = mtree_store_range(&region->vm_mm->region_tree, region->vm_start, region->vm_end - 1,
                               region, GFP_KERNEL);
    CHECK(st == 0);
    validate_mm_tree(region->vm_mm);
    return 0;
}

static int vm_expand_mapping(struct mm_address_space *as, struct vm_area_struct *region,
                             size_t new_size) REQUIRES(as->vm_lock)
{
    if (!vm_can_expand(as, region, new_size))
        return -1;

    return __vm_expand_mapping(region, new_size);
}

static int vm_expand_brk(struct mm_address_space *as, size_t nr_pages) REQUIRES(as->vm_lock)
{
    struct vm_area_struct *brk_region = vm_find_region(as, as->brk);
    assert(brk_region != NULL);
    size_t new_size = (vma_pages(brk_region) + nr_pages) << PAGE_SHIFT;

    return vm_expand_mapping(as, brk_region, new_size);
}

static int mremap_check_for_overlap(void *__old_address, size_t old_size, void *__new_address,
                                    size_t new_size)
{
    unsigned long old_address = (unsigned long) __old_address;
    unsigned long new_address = (unsigned long) __new_address;

    /* Written at 03:00, but the logic looks good? */
    if (old_address <= (unsigned long) new_address &&
        old_address + old_size > (unsigned long) new_address)
        return -1;
    if (old_address <= (unsigned long) new_address + new_size &&
        old_address + old_size > (unsigned long) new_address + new_size)
        return -1;
    return 0;
}

void *vm_remap_create_new_mapping_of_shared_pages(struct mm_address_space *mm, void *new_address,
                                                  size_t new_size, int flags, void *old_address)
    REQUIRES(mm->vm_lock)
{
    return (void *) -ENOMEM;
}

static void *vm_try_move(struct mm_address_space *mm, struct vm_area_struct *old_region,
                         unsigned long new_base, size_t new_size) REQUIRES(mm->vm_lock)
{
    return (void *) -ENOMEM;
}

static void *vm_remap_try(struct mm_address_space *as, void *old_address, size_t old_size,
                          void *new_address, size_t new_size, int flags) REQUIRES(as->vm_lock)
{
    return (void *) -ENOMEM;
}

static bool limits_are_contained(struct vm_area_struct *reg, unsigned long start,
                                 unsigned long limit)
{
    unsigned long reg_limit = reg->vm_end;

    if (start <= reg->vm_start && limit > reg->vm_start)
        return true;
    if (reg->vm_start <= start && reg_limit >= limit)
        return true;

    return false;
}

/* TODO: Test things */
void *sys_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address)
{
    // TODO: This is broken.
    WARN_ON_ONCE(1);
    return (void *) -ENOSYS;
    /* Check http://man7.org/linux/man-pages/man2/mremap.2.html for documentation */
    bool may_move = flags & MREMAP_MAYMOVE;
    bool fixed = flags & MREMAP_FIXED;
    bool wants_create_new_mapping_of_pages = old_size == 0 && may_move;
    void *ret = MAP_FAILED;
    struct mm_address_space *as = get_current_address_space();

    /* TODO: Unsure on what to do if new_size > old_size */

    if (vm_sanitize_address(old_address, old_size >> PAGE_SHIFT) < 0)
    {
        ret = (void *) -EFAULT;
        goto out;
    }

    if (wants_create_new_mapping_of_pages)
        return vm_remap_create_new_mapping_of_shared_pages(as, new_address, new_size, flags,
                                                           old_address);

    if (old_size == 0)
    {
        ret = (void *) -EINVAL;
        goto out;
    }

    if (new_size == 0)
    {
        ret = (void *) -EINVAL;
        goto out;
    }

    if (!fixed)
    {
        ret = vm_remap_try(as, old_address, old_size, new_address, new_size, flags);
        goto out;
    }
    else
    {

        if (vm_sanitize_address(new_address, new_size >> PAGE_SHIFT) < 0)
        {
            ret = (void *) -EINVAL;
            goto out;
        }

        if (mremap_check_for_overlap(old_address, old_size, new_address, new_size) < 0)
        {
            ret = (void *) -EINVAL;
            goto out;
        }

        struct vm_area_struct *reg = vm_find_region(as, old_address);
        if (!reg)
        {
            ret = (void *) -EFAULT;
            goto out;
        }
#if 0
        struct vm_area_struct *old_reg =
            vm_split_region(as, reg, (unsigned long) old_address, old_size, &n);
        if (!old_reg)
        {
            ret = (void *) -ENOMEM;
            goto out;
        }

        __vm_munmap(as, new_address, new_size);

        ret = vm_try_move(as, old_reg, (unsigned long) new_address, new_size);
#endif
    }

out:
    return ret;
}

void vm_wp_page(struct mm_address_space *mm, void *vaddr)
{
    if (paging_write_protect(vaddr, mm))
        mmu_invalidate_range((unsigned long) vaddr, 1, mm);
}

static int get_phys_pages_direct(unsigned long addr, unsigned int flags, struct page **pages,
                                 size_t nr_pgs)
{
    if (flags & GPP_USER)
        return GPP_ACCESS_FAULT;

    /* This is a PFNMAP kind of thing, so we don't have pages to reference.
     * We'll just need to pretend each paddr is a page struct and tell the caller at the
     * end, using GPP_ACCESS_PFNMAP.
     */

    for (size_t i = 0; i < nr_pgs; i++, addr += PAGE_SIZE)
    {
        unsigned long paddr = addr - PHYS_BASE;
        struct page *p = phys_to_page(paddr);
        pages[i] = p;
        page_ref(p);
    }

    return GPP_ACCESS_OK | GPP_ACCESS_PFNMAP;
}

static int gpp_try_to_fault_in(unsigned long addr, struct vm_area_struct *entry, unsigned int flags)
{
    struct fault_info finfo;
    finfo.signal = 0;
    finfo.exec = false;
    finfo.fault_address = addr;
    finfo.ip = 0;
    finfo.read = flags & GPP_READ;
    finfo.user = true;
    finfo.write = flags & GPP_WRITE;

    if (__vm_handle_pf(entry, &finfo) < 0)
    {
        return GPP_ACCESS_FAULT;
    }

    return GPP_ACCESS_OK;
}

static struct page *page_from_pte(pte_t *pte, struct vm_area_struct *vma, unsigned int flags,
                                  struct spinlock *lock)
{
    struct page *page = NULL;
    unsigned long addr;

    if (pte_none(*pte))
    {
        /* We should fault the page in, except if this is part of a coredump process; in that case
         * we want to skip writing out and faulting in anon zero pages to disk. */
        if (flags & GPP_DUMP && vm_mapping_is_anon(vma))
        {
            page = ERR_PTR(-ENODATA);
            goto nopage;
        }
    }

    if (!pte_present(*pte))
        goto nopage;

    /* coredumps want protnone pages - so pass them with no problem */
    if (pte_protnone(*pte) && (flags & GPP_READ) && !(flags & GPP_DUMP))
        goto nopage;

    if (flags & GPP_WRITE && !pte_write(*pte))
        goto nopage;

    addr = pte_addr(*pte);
    page = phys_to_page(addr);

    if (unlikely(flags & GPP_DUMP && page == vm_zero_page))
        page = ERR_PTR(-ENODATA);
    else
        page_ref(page);
nopage:
    spin_unlock(lock);
    return page;
}

static int __get_phys_pages(struct vm_area_struct *region, unsigned long addr, unsigned int flags,
                            struct page **pages, size_t nr_pgs)
{
    struct spinlock *lock;
    pte_t *pte;
    struct page *page;
    int st;

    for (size_t i = 0; i < nr_pgs; i++, addr += PAGE_SIZE)
    {
    retry:;
        /* TODO: Walking this properly (and this logic being a callback) would be better */
        pte = ptep_get_locked(region->vm_mm, addr, &lock);
        if (!pte)
            goto fault_in;

        page = page_from_pte(pte, region, flags, lock);
        if (IS_ERR(page))
        {
            /* Ok, we're coredumping and found pages we were going to fault in as zero, or were
             * already zero. Skip these. */
            WARN_ON(!(flags & GPP_DUMP));
            WARN_ON(PTR_ERR(page) != -ENODATA);
            pages[i] = NULL;
            continue;
        }
        else if (page == NULL)
            goto fault_in;

        pages[i] = page;
        continue;
    fault_in:
        st = gpp_try_to_fault_in(addr, region, flags);
        /* TODO: Recovery path is funky and we're not cleaning up pages properly */
        if (!(st & GPP_ACCESS_OK))
            return st;
        goto retry;
    }

    return GPP_ACCESS_OK;
}

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
int get_phys_pages(void *_addr, unsigned int flags, struct page **pages, size_t nr_pgs)
{
    int ret = GPP_ACCESS_OK;
    bool had_shared_pages = false;
    struct mm_address_space *mm = get_current_address_space();

    unsigned long addr = (unsigned long) _addr;

    if (addr >= PHYS_BASE && (addr + (nr_pgs << PAGE_SHIFT)) < PHYS_BASE_LIMIT)
    {
        ret = get_phys_pages_direct(addr, flags, pages, nr_pgs);
        return ret;
    }

    rw_lock_read(&mm->vm_lock);
    size_t pages_gotten = 0;

    while (nr_pgs)
    {
        struct vm_area_struct *reg = vm_find_region(mm, (void *) addr);

        if (!reg)
        {
            ret = GPP_ACCESS_FAULT;
            goto out;
        }

        if (vma_shared(reg))
            had_shared_pages = true;

        /* Do a permission check. */
        unsigned int rwx_mask = (flags & GPP_READ ? VM_READ : 0) |
                                (flags & GPP_WRITE ? VM_WRITE : 0) |
                                (flags & GPP_USER ? VM_USER : 0);

        if ((reg->vm_flags & rwx_mask) != rwx_mask && !(flags & GPP_DUMP))
        {
            ret = GPP_ACCESS_FAULT;
            goto out;
        }

        /* Calculate the number of pages we can resolve in this region */
        size_t vm_area_struct_off_pgs = (reg->vm_start - addr) >> PAGE_SHIFT;
        size_t max_resolved_pgs = reg->vm_end - reg->vm_start - vm_area_struct_off_pgs;
        size_t resolved_pgs = min(nr_pgs, max_resolved_pgs);

        /* And now resolve stuff */
        ret = __get_phys_pages(reg, addr, flags, pages + pages_gotten, resolved_pgs);

        /* Bail if we've hit an error */
        if (!(ret & GPP_ACCESS_OK))
            goto out;

        nr_pgs -= resolved_pgs;
        pages_gotten += resolved_pgs;
        addr += nr_pgs << PAGE_SHIFT;
    }

out:
    if (ret & GPP_ACCESS_OK && had_shared_pages)
        ret |= GPP_ACCESS_SHARED;
    rw_unlock_read(&mm->vm_lock);
    return ret;
}

static int do_sync(struct file *file, unsigned long start, unsigned long end)
{
    struct writepages_info wp;
    wp.start = start >> PAGE_SHIFT;
    wp.end = (end - 1) >> PAGE_SHIFT;
    wp.flags = WRITEPAGES_SYNC;
    if (file->f_op->fsyncdata)
        return file->f_op->fsyncdata(file->f_ino, &wp);
    return -EINVAL;
}

/**
 * @brief Retrieves a pointer to the zero page.
 *
 * @return Pointer to the zero page's struct page.
 */
struct page *vm_get_zero_page()
{
    return vm_zero_page;
}

int sys_msync(void *ptr, size_t length, int flags)
{
    /* The only flag that needs action upon is MS_SYNC, the rest is a no-op. */
    int st = -ENOMEM;
    unsigned long addr = (unsigned long) ptr;
    unsigned long limit = addr + length;
    struct mm_address_space *as = get_current_address_space();

    if (flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE))
        return -EINVAL;

    if (addr & (PAGE_SIZE - 1))
        return -EINVAL;

    /* Hogging the vm_lock is bad mkay, todo... */
    rw_lock_read(&as->vm_lock);

    struct vm_area_struct *vma = vm_search(as, (void *) addr, length);

    if (vma)
    {
        /* Check if start <= addr */
        if (vma->vm_start > addr)
            goto enomem;
        /* The first vma may have a gap wrt the addr, so readjust it */
        addr = vma->vm_start;
    }
    else
        goto enomem;

    VMA_ITERATOR(vmi, as, addr, limit);
    mas_for_each(&vmi.mas, vma, vmi.end)
    {
        /* We must watch out for gaps in the address space and -ENOMEM there */
        if (vma->vm_start != addr)
            break;
        if (vma->vm_start > limit || vma->vm_end < addr)
            break;
        unsigned long to_sync = min(length, vma->vm_end - addr);
        struct file *filp = vma->vm_file;

        if (flags & MS_SYNC && filp && vma_shared(vma))
        {
            unsigned long start = vma->vm_offset + addr - vma->vm_start;
            unsigned long end = start + to_sync;
            int st2 = do_sync(filp, start, end);
            if (st2 < 0)
            {
                st = st2;
                break;
            }
        }

        addr += to_sync;
        length -= to_sync;
        if (!length)
        {
            st = 0;
            break;
        }
    }

    vmi_destroy(&vmi);
enomem:
    rw_unlock_read(&as->vm_lock);
    return st;
}

static inline void mm_init(struct mm_address_space *mm)
{
    memset(mm, 0, sizeof(*mm));
    mm->mm_count = REFCOUNT_INIT(1);
    mm->mm_users = REFCOUNT_INIT(1);
    rwlock_init(&mm->vm_lock);
    mm->region_tree = (struct maple_tree) MTREE_INIT(mm->region_tree,
                                                     MT_FLAGS_ALLOC_RANGE | MT_FLAGS_LOCK_EXTERN);
    spin_lock_init(&mm->page_table_lock);
}

/**
 * @brief Creates a new standalone address space
 *
 * @return Ref guard to a mm_address_space, or a negative status code
 */
struct mm_address_space *mm_create(void)
{
    struct mm_address_space *mm = (struct mm_address_space *) kmalloc(sizeof(*mm), GFP_KERNEL);
    if (!mm)
        return ERR_PTR(-ENOMEM);

    mm_init(mm);
    int st = vm_clone_as(mm, get_current_address_space());
    if (st < 0)
    {
        kfree(mm);
        return ERR_PTR(-ENOMEM);
    }

    return mm;
}

/**
 * @brief Creates a new standalone address space by forking
 *
 * @return Ref guard to a mm_address_space, or a negative status code
 */
struct mm_address_space *mm_fork(void)
{
    // TRACE_EVENT_DURATION(vm_fork_mm);
    struct mm_address_space *mm = (struct mm_address_space *) kmalloc(sizeof(*mm), GFP_KERNEL);
    if (!mm)
        return (void *) ERR_PTR(-ENOMEM);

    mm_init(mm);
    int st = vm_fork_address_space(mm);
    if (st < 0)
    {
        return ERR_PTR(st);
    }

    return mm;
}

/**
 * @brief Loads an address space
 *
 * @param aspace Address space to load
 * @param cpu CPU we're on
 */
void vm_load_aspace(struct mm_address_space *aspace, unsigned int cpu)
{
    if (unlikely(cpu == -1U))
        cpu = get_cpu_nr();
    cpumask_set_atomic(&aspace->active_mask, cpu);
    vm_load_arch_mmu(&aspace->arch_mmu);
}

/**
 * @brief Sets the current address space, and returns the old one
 *
 * @param aspace Address space to set and load
 * @return The old address space
 */
struct mm_address_space *vm_set_aspace(struct mm_address_space *aspace)
{
    struct mm_address_space *ret = &kernel_address_space;
    struct thread *thread = get_current_thread();
    if (thread)
    {
        ret = thread->aspace;
        thread->aspace = aspace;
    }

    vm_load_aspace(aspace, -1);

    return ret;
}

void __mmdrop(struct mm_address_space *mm)
{
    /* Last drop, mm has no users and no lazy users, free the last bits and goodbye. */
    CHECK(refcount_read(&mm->mm_users) == 0);
    if (vm_get_fallback_pgd() != vm_get_pgd(&mm->arch_mmu))
        vm_free_arch_mmu(&mm->arch_mmu);
    kfree(mm);
}

void __mmput(struct mm_address_space *mm)
{
    /* mm has no users, clear out the address space and put the implicit ref. The pgd is not freed
     * and the kernel page tables will be unharmed. */
    vm_destroy_addr_space(mm);
    mmdrop(mm);
}

unsigned long get_mapping_info(void *addr)
{
    struct mm_address_space *as = &kernel_address_space;
    if ((unsigned long) addr < VM_HIGHER_HALF)
        as = get_current_address_space();

    return __get_mapping_info(addr, as);
}

bool paging_change_perms(void *addr, int prot)
{
    struct mm_address_space *as = &kernel_address_space;
    if ((unsigned long) addr < VM_HIGHER_HALF)
        as = get_current_address_space();

    return __paging_change_perms(as, addr, prot);
}

struct mm_address_space *get_remote_mm(struct process *task)
{
    struct mm_address_space *mm;
    spin_lock(&task->alloc_lock);
    mm = task->address_space;
    if (!mm || mm == &kernel_address_space)
        mm = NULL;
    else
        mmget(mm);
    spin_unlock(&task->alloc_lock);
    return mm;
}

struct proc_maps_info
{
    struct process *task;
    struct mm_address_space *mm;
    struct vma_iterator vmi;
};

static struct vm_area_struct *vmi_next(struct vma_iterator *vmi)
{
    return mas_find(&vmi->mas, -1UL);
}

static void *maps_start(struct seq_file *m, off_t *off)
{
    struct proc_maps_info *info = m->private;
    struct vm_area_struct *vma;
    info->mm = get_remote_mm(info->task);
    if (!info->mm)
        return NULL;

    rw_lock_read(&info->mm->vm_lock);
    vmi_init(&info->vmi, info->mm, *off, -1UL);
    vma = vmi_next(&info->vmi);
    if (vma)
        *off = vma->vm_start;
    return vma;
}

static void maps_stop(struct seq_file *m, void *ptr)
{
    struct proc_maps_info *info = m->private;
    rw_unlock_read(&info->mm->vm_lock);
    mmput(info->mm);
    info->mm = NULL;
}

static void *maps_next(struct seq_file *m, void *ptr, off_t *pos)
{
    struct proc_maps_info *info = m->private;
    struct vm_area_struct *vma, *old = ptr;

    vma = vmi_next(&info->vmi);
    if (vma)
        *pos = vma->vm_start;
    else
        *pos = old->vm_end;
    return vma;
}

static int print_d_path(struct seq_file *m, struct file *filp)
{
    unsigned int bufsize = 64;
    char *buf, *path;
    int err = 0;

    buf = kmalloc(bufsize, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

again:
    path = d_path(&filp->f_path, buf, bufsize);
    if (IS_ERR(path))
    {
        if (PTR_ERR(path) == -ENAMETOOLONG)
        {
            bufsize <<= 1;
            char *buf2 = krealloc(buf, bufsize, GFP_KERNEL);
            if (!buf2)
            {
                err = -ENOMEM;
                goto out;
            }
            buf = buf2;
            goto again;
        }

        /* This shouldn't happen, but just keep going in case of an unspecified failure */
        return 0;
    }

    seq_puts(m, path);
out:
    kfree(buf);
    return err;
}

static int maps_show_name(struct seq_file *m, struct vm_area_struct *vma)
{
    struct file *filp = vma->vm_file;

    if (!filp)
    {
        /* Anon. For now, lets not print anything (since we don't know what's brk or stack or
         * whatnot) */
        return 0;
    }

    seq_putc(m, ' ');
    seq_puts(m, "\t\t");
    if (filp->f_path.mount)
        return print_d_path(m, filp);
    /* Just print the dentry's name, it ought to be fine... */
    rcu_read_lock();
    seq_puts(m, filp->f_dentry->d_name);
    rcu_read_unlock();
    return 0;
}

static int maps_show(struct seq_file *m, void *ptr)
{
    struct vm_area_struct *vma = ptr;
    int flags = vma->vm_flags;
    bool anon = vma->vm_file == NULL;
    int err;

    seq_printf(m, "%08lx-%08lx %c%c%c%c ", vma->vm_start, vma->vm_end, flags & VM_READ ? 'r' : '-',
               flags & VM_WRITE ? 'w' : '-', flags & VM_EXEC ? 'x' : '-',
               flags & VM_SHARED ? 's' : 'p');
    if (anon)
    {
        /* Zero off, dev, inode */
        seq_puts(m, "00000000 00:00 0");
    }
    else
    {
        struct file *filp = vma->vm_file;
        struct inode *ino = filp->f_ino;
        seq_printf(m, "%08lx %02x:%02x %lx", vma->vm_offset, MAJOR(ino->i_dev), MINOR(ino->i_dev),
                   ino->i_inode);
    }

    err = maps_show_name(m, vma);
    if (err)
        return err;
    seq_putc(m, '\n');
    return 0;
}

static const struct seq_operations maps_ops = {
    .start = maps_start,
    .stop = maps_stop,
    .next = maps_next,
    .show = maps_show,
};

int proc_maps_open(struct file *filp)
{
    int err;
    struct proc_maps_info *info;

    info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info)
        return -ENOMEM;
    info->task = get_inode_task((struct procfs_inode *) filp->f_ino);
    if (!info->task)
    {
        kfree(info);
        return -ENOMEM;
    }

    info->mm = NULL;
    err = seq_open(filp, &maps_ops);
    if (err < 0)
    {
        process_put(info->task);
        kfree(info);
        return err;
    }

    ((struct seq_file *) filp->private_data)->private = info;
    return err;
}

static void proc_maps_release(struct file *filp)
{
    struct seq_file *m = filp->private_data;
    struct proc_maps_info *info = m->private;
    process_put(info->task);
    kfree(info);
    seq_release(filp);
}

const struct proc_file_ops proc_maps_ops = {
    .open = proc_maps_open,
    .read_iter = seq_read_iter,
    .release = proc_maps_release,
};
