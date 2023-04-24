/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

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
#include <onyx/dev.h>
#include <onyx/file.h>
#include <onyx/log.h>
#include <onyx/mm/kasan.h>
#include <onyx/mm/slab.h>
#include <onyx/mm/vm_object.h>
#include <onyx/page.h>
#include <onyx/pagecache.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/spinlock.h>
#include <onyx/sysfs.h>
#include <onyx/timer.h>
#include <onyx/user.h>
#include <onyx/utils.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>
#include <onyx/vm_layout.h>

#include <libdict/dict.h>
#include <uapi/fcntl.h>
#include <uapi/memstat.h>

bool is_initialized = false;
static bool enable_aslr = true;

uintptr_t high_half = arch_high_half;
uintptr_t low_half_max = arch_low_half_max;
uintptr_t low_half_min = arch_low_half_min;

/* These addresses are either absolute, or offsets, depending on the architecture.
 * The corresponding arch/ code is responsible for patching these up using
 * vm_update_addresses.
 */
uintptr_t vmalloc_space = arch_vmalloc_off;
uintptr_t kstacks_addr = arch_kstacks_off;
uintptr_t heap_addr = arch_heap_off;
size_t heap_size = 0;

void kmalloc_init();
int populate_shared_mapping(void *page, struct file *fd, struct vm_region *entry, size_t nr_pages);
void vm_remove_region(struct mm_address_space *as, struct vm_region *region);
int vm_add_region(struct mm_address_space *as, struct vm_region *region);
void remove_vmo_from_private_list(struct mm_address_space *mm, struct vm_object *vmo);
void add_vmo_to_private_list(struct mm_address_space *mm, struct vm_object *vmo);
bool vm_using_shared_optimization(struct vm_region *region);
int __vm_munmap(struct mm_address_space *as, void *__addr, size_t size);
void vm_unmap_every_region_in_range(struct mm_address_space *as, unsigned long start,
                                    unsigned long length);
bool limits_are_contained(struct vm_region *reg, unsigned long start, unsigned long limit);
bool vm_mapping_is_cow(struct vm_region *entry);

bool vm_test_vs_rlimit(const mm_address_space *as, ssize_t diff)
{
    /* The kernel doesn't have resource limits */
    if (as == &kernel_address_space)
        return true;
    /* Decreasing the resource usage doesn't respect limits */
    if (diff < 0)
        return true;
    return get_current_process()->get_rlimit(RLIMIT_AS).rlim_cur >=
           as->virtual_memory_size + (size_t) diff;
}

int imax(int x, int y)
{
    return x > y ? x : y;
}

uintptr_t max(uintptr_t x, uintptr_t y)
{
    return x > y ? x : y;
}

#define KADDR_SPACE_SIZE 0x800000000000
#define KADDR_START      0xffff800000000000

constinit struct mm_address_space kernel_address_space = {};

int vm_cmp(const void *k1, const void *k2)
{
    if (k1 == k2)
        return 0;

    return (unsigned long) k1 < (unsigned long) k2 ? -1 : 1;
}

static struct page *vm_zero_page = nullptr;

static struct slab_cache *vm_region_cache = nullptr;

static inline vm_region *vm_alloc_vmregion()
{
    return (vm_region *) kmem_cache_alloc(vm_region_cache, 0);
}

static inline void vm_free_vmregion(vm_region *region)
{
    kmem_cache_free(vm_region_cache, (void *) region);
}

bool vm_insert_region(struct mm_address_space *as, struct vm_region *region)
{
    return bst_insert(
        &as->region_tree, &region->tree_node,
        [](struct bst_node *lhs_, struct bst_node *rhs_) -> int {
            auto lhs = container_of(lhs_, vm_region, tree_node);
            auto rhs = container_of(rhs_, vm_region, tree_node);

            if (check_for_overlap(lhs->base, lhs->base + (lhs->pages << PAGE_SHIFT) - 1, rhs->base,
                                  rhs->base + (rhs->pages << PAGE_SHIFT) - 1))
            {
                panic("vm_insert_region: Region [%lx, %lx] and [%lx, %lx] overlap\n", lhs->base,
                      lhs->base + (lhs->pages << PAGE_SHIFT), rhs->base,
                      rhs->base + (rhs->pages << PAGE_SHIFT));
                return 0;
            }
            else if (rhs->base > lhs->base)
                return 1;
            else
                return -1;
        });
}

struct vm_region *vm_reserve_region(struct mm_address_space *as, unsigned long start, size_t size)
{
    MUST_HOLD_MUTEX(&as->vm_lock);

    struct vm_region *region = vm_alloc_vmregion();
    if (!region)
        return nullptr;

    memset(region, 0, sizeof(*region));

    region->base = start;
    region->pages = vm_size_to_pages(size);
    region->rwx = 0;
    bst_node_initialize(&region->tree_node);

    bool success =
        bst_insert(&as->region_tree, &region->tree_node,
                   [](struct bst_node *lhs_, struct bst_node *rhs_) -> int {
                       auto lhs = container_of(lhs_, vm_region, tree_node);
                       auto rhs = container_of(rhs_, vm_region, tree_node);

                       if (check_for_overlap(lhs->base, lhs->base + (lhs->pages << PAGE_SHIFT) - 1,
                                             rhs->base, rhs->base + (rhs->pages << PAGE_SHIFT) - 1))
                       {
                           panic("vm_reserve_region: Region [%lx, %lx] and [%lx, %lx] overlap\n",
                                 lhs->base, lhs->base + (lhs->pages << PAGE_SHIFT), rhs->base,
                                 rhs->base + (rhs->pages << PAGE_SHIFT));
                           return 0;
                       }
                       else if (rhs->base > lhs->base)
                           return 1;
                       else
                           return -1;
                   });

    if (!success)
    {
        panic("Could not insert vm region [%lx, %lx]", start,
              start + (region->pages << PAGE_SHIFT) - 1);
    }

    region->mm = as;

    return region;
}

#define DEBUG_VM_1 0
#define DEBUG_VM_2 0
#define DEBUG_VM_3 0

unsigned long vm_allocate_base(struct mm_address_space *as, unsigned long min, size_t size)
{
    MUST_HOLD_MUTEX(&as->vm_lock);

    if (min < as->start)
        min = as->start;

    struct a : bst_node
    {
        unsigned long min;
    } priv;

    priv.min = min;

    auto compare = [](bst_node *node0, bst_node *fake) -> int {
        struct a *priv = (a *) fake;
        auto reg = container_of(node0, vm_region, tree_node);
        auto end = reg->base + (reg->pages << PAGE_SHIFT) - 1;
        if (check_for_overlap(reg->base, end, priv->min, priv->min + PAGE_SIZE))
            return 0;
        else if (end >= priv->min)
            return -1;
        else // if (end < priv->min)
            return 1;
    };

    struct bst_node *node = nullptr;
    unsigned long last_end = min;
    struct vm_region *f = nullptr;

    if (min != as->start)
    {
        node = bst_search(&as->region_tree, &priv, compare);
    }
    else
    {
        node = bst_min(&as->region_tree, nullptr);
    }

    if (!node)
        goto done;

    /* Check if there's a gap between the first node
     * and the start of the address space
     */

    f = container_of(node, vm_region, tree_node);

#if DEBUG_VM_1
    printk("Tiniest node: %016lx\n", f->base);
#endif
    if (f->base - min >= size)
    {
#if DEBUG_VM_2
        printk("gap [%016lx - %016lx]\n", min, f->base);
#endif
        goto done;
    }

    while (node)
    {
        f = container_of(node, vm_region, tree_node);
        last_end = f->base + (f->pages << PAGE_SHIFT);

        node = bst_next(&as->region_tree, node);
        if (!node)
            break;

        struct vm_region *vm = container_of(node, vm_region, tree_node);

        if (vm->base - last_end >= size && min <= vm->base)
            break;
    }

done:
#if DEBUG_VM_3
    if (as == &kernel_address_space && min == kstacks_addr)
        printk("Ptr: %lx\nSize: %lx\n", last_end, size);
#endif
    last_end = last_end < min ? min : last_end;
#if DEBUG_VM_3
    if (as == &kernel_address_space && min == kstacks_addr)
        printk("Ptr: %lx\nSize: %lx\n", last_end, size);
#endif

    return last_end;
}

struct vm_region *vm_allocate_region(struct mm_address_space *as, unsigned long min, size_t size)
{
    if (!vm_test_vs_rlimit(as, size))
        return errno = ENOMEM, nullptr;

    unsigned long new_base = vm_allocate_base(as, min, size);

    assert((new_base & (PAGE_SIZE - 1)) == 0);

    struct vm_region *reg = vm_reserve_region(as, new_base, size);

    if (reg)
    {
        increment_vm_stat(as, virtual_memory_size, size);
    }

    return reg;
}

void vm_addr_init()
{
    kernel_address_space.start = KADDR_START;
    kernel_address_space.end = UINTPTR_MAX;

    // Permanent reference
    kernel_address_space.ref();
}

static inline void __vm_lock(bool kernel)
{
    if (kernel)
        mutex_lock(&kernel_address_space.vm_lock);
    else
        mutex_lock(&get_current_address_space()->vm_lock);
}

static inline void __vm_unlock(bool kernel)
{
    if (kernel)
        mutex_unlock(&kernel_address_space.vm_lock);
    else
        mutex_unlock(&get_current_address_space()->vm_lock);
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

void heap_set_start(uintptr_t start);

/**
 * @brief Initialises the architecture independent parts of the VM subsystem.
 *
 */
void vm_late_init()
{
    /* TODO: This should be arch specific stuff, move this to arch/ */
    uintptr_t heap_addr_no_aslr = heap_addr;
    const auto vmalloc_noaslr = vmalloc_space;

    kstacks_addr = vm_randomize_address(kstacks_addr, KSTACKS_ASLR_BITS);
    vmalloc_space = vm_randomize_address(vmalloc_space, VMALLOC_ASLR_BITS);
    heap_addr = vm_randomize_address(heap_addr, HEAP_ASLR_BITS);

    // Initialize vmalloc first. This will feed the rest of the allocators.
    const auto vmalloc_len = VM_VMALLOC_SIZE - (vmalloc_space - vmalloc_noaslr);

    vmalloc_init(vmalloc_space, vmalloc_len);
    // Now initialize slabs for kmalloc

    kmalloc_init();

    vm_region_cache = kmem_cache_create("vm_region", sizeof(vm_region), 0, 0, nullptr);

    if (!vm_region_cache)
        panic("vm: early boot oom");

    heap_set_start(heap_addr);

    vm_addr_init();

    heap_size = arch_heap_get_size() - (heap_addr - heap_addr_no_aslr);
    scoped_mutex g{kernel_address_space.vm_lock};

    /* Start populating the address space */
    struct vm_region *v = vm_reserve_region(&kernel_address_space, heap_addr, heap_size);
    if (!v)
    {
        panic("vmm: early boot oom");
    }

    v->type = VM_TYPE_HEAP;
    v->rwx = VM_WRITE | VM_READ;

    struct kernel_limits l;
    get_kernel_limits(&l);
    size_t kernel_size = l.end_virt - l.start_virt;

    v = vm_reserve_region(&kernel_address_space, l.start_virt, kernel_size);
    if (!v)
    {
        panic("vmm: early boot oom");
    }

    v->type = VM_TYPE_REGULAR;
    v->rwx = VM_WRITE | VM_READ | VM_EXEC;

    v = vm_reserve_region(&kernel_address_space, vmalloc_space, vmalloc_len);

    if (!v)
    {
        panic("vmm: early boot oom");
    }

    v->type = VM_TYPE_REGULAR;
    v->rwx = VM_WRITE | VM_READ;

    vm_zero_page = alloc_page(0);
    assert(vm_zero_page != nullptr);

    is_initialized = true;
}

/**
 * @brief Maps a range of memory with freshly allocated anonymous pages.
 * This should only be used by very-specific MM or MM related code.
 * @param range Virtual address.
 * @param pages Number of pages to be mapped.
 * @param flags Protection on the mappings.
 * @return The list of allocated pages, or NULL if there was an out of memory scenario.
 */
struct page *vm_map_range(void *range, size_t nr_pages, uint64_t flags)
{
    const unsigned long mem = (unsigned long) range;
    struct page *pages = alloc_pages(nr_pages, 0);
    struct page *p = pages;
    if (!pages)
        goto out_of_mem;

#ifdef DEBUG_PRINT_MAPPING
    printk("vm_map_range: %p - %lx\n", range, (unsigned long) range + nr_pages << PAGE_SHIFT);
#endif

    for (size_t i = 0; i < nr_pages; i++)
    {
        // printf("Mapping %p\n", p->paddr);
        if (!vm_map_page(nullptr, mem + (i << PAGE_SHIFT), (uintptr_t) page_to_phys(p), flags))
            goto out_of_mem;
        p = p->next_un.next_allocation;
    }

    return pages;

out_of_mem:
    if (pages)
        free_pages(pages);
    return nullptr;
}

void do_vm_unmap(void *range, size_t pages)
{
    struct vm_region *entry = vm_find_region(range);
    assert(entry != nullptr);

    MUST_HOLD_MUTEX(&entry->mm->vm_lock);

    vm_mmu_unmap(entry->mm, range, pages);
}

void __vm_unmap_range(void *range, size_t pages)
{
    do_vm_unmap(range, pages);
}

/**
 * @brief Unmaps a range of pages on the current address space.
 *
 * @param range The start of the virtual range.
 * @param pages The number of pages.
 */
void vm_unmap_range(void *range, size_t pages)
{
    bool kernel = is_higher_half(range);

    __vm_lock(kernel);

    __vm_unmap_range(range, pages);
    __vm_unlock(kernel);
}

static inline bool inode_requires_wb(struct inode *i)
{
    return i->i_type == VFS_TYPE_FILE;
}

bool vm_mapping_requires_wb(struct vm_region *reg)
{
    return reg->mapping_type == MAP_SHARED && reg->fd && inode_requires_wb(reg->fd->f_ino);
}

bool vm_mapping_is_anon(struct vm_region *reg)
{
    return reg->fd == nullptr && reg->vmo->type == VMO_ANON;
}

/**
 * @brief Transforms a file-backed region into an anonymously backed one.
 *
 * @param region A pointer to the vm_region.
 */
void vm_make_anon(struct vm_region *reg)
{
    if (reg->fd)
    {
        fd_put(reg->fd);
        reg->fd = nullptr;
    }

    reg->flags |= MAP_ANONYMOUS;
}

bool vm_mapping_requires_write_protect(struct vm_region *reg)
{
    return vm_mapping_requires_wb(reg);
}

void vm_region_destroy(struct vm_region *region)
{
    MUST_HOLD_MUTEX(&region->mm->vm_lock);

    /* First, unref things */
    if (region->fd)
    {
        fd_put(region->fd);
    }

    if (region->vmo)
    {
        if (region->vmo->refcount == 1)
        {
            if (!is_mapping_shared(region) && !is_higher_half((void *) region->base))
                remove_vmo_from_private_list(region->mm, region->vmo);
        }

        vmo_remove_mapping(region->vmo, region);
        vmo_unref(region->vmo);
    }

    memset_explicit(region, 0xfd, sizeof(struct vm_region));

    vm_free_vmregion(region);
}

/**
 * @brief Unmaps a region under a specified range.
 * Note: This function is deprecated.
 *
 * @param range Start of the range.
 * @param pages Number of pages.
 */
void vm_destroy_mappings(void *range, size_t pages)
{
    struct mm_address_space *mm =
        is_higher_half(range) ? &kernel_address_space : get_current_process()->get_aspace();

    scoped_mutex g{mm->vm_lock};

    struct vm_region *reg = vm_find_region(range);

    vm_unmap_range(range, pages);

    bst_delete(&mm->region_tree, &reg->tree_node);

    if (is_mapping_shared(reg))
        decrement_vm_stat(mm, shared_set_size, pages << PAGE_SHIFT);

    vm_region_destroy(reg);

    decrement_vm_stat(mm, virtual_memory_size, pages << PAGE_SHIFT);
}

unsigned long vm_get_base_address(uint64_t flags, uint32_t type)
{
    bool is_kernel_map = flags & VM_KERNEL;
    struct mm_address_space *mm = nullptr;

    if (!is_kernel_map)
    {
        mm = get_current_address_space();
    }

    switch (type)
    {
        case VM_TYPE_SHARED:
        case VM_TYPE_STACK: {
            if (is_kernel_map)
                return kstacks_addr;
            else
                return (uintptr_t) mm->mmap_base;
        }

        case VM_TYPE_MODULE: {
            assert(is_kernel_map == true);

            return KERNEL_VIRTUAL_BASE;
        }

        default:
        case VM_TYPE_REGULAR: {
            if (is_kernel_map)
                return vmalloc_space;
            else
                return (uintptr_t) mm->mmap_base;
        }
    }
}

struct vm_region *__vm_allocate_virt_region(uint64_t flags, size_t pages, uint32_t type,
                                            uint64_t prot)
{
    bool allocating_kernel = true;
    if (flags & VM_ADDRESS_USER)
        allocating_kernel = false;

    struct mm_address_space *as =
        allocating_kernel ? &kernel_address_space : get_current_address_space();

    MUST_HOLD_MUTEX(&as->vm_lock);

    unsigned long base_addr = vm_get_base_address(flags, type);

    struct vm_region *region = vm_allocate_region(as, base_addr, pages << PAGE_SHIFT);

    if (region)
    {
        if (prot & (VM_WRITE | VM_EXEC))
            prot |= VM_READ;
        region->rwx = prot;
        region->type = type;
    }

    return region;
}

/**
 * @brief Allocates a new virtual region in the current address space.
 * This should *NOT* be used by non-mm code.
 *
 * @param flags Flags for the allocation (VM_KERNEL, VM_ADDRESS_USER).
 * @param pages Number of pages required.
 * @param type Type of the vm region; this affects the placement.
 * @param prot Protection of the vm region (VM_WRITE, NOEXEC, etc).
 * @return A pointer to the new vm region.
 */
struct vm_region *vm_allocate_virt_region(uint64_t flags, size_t pages, uint32_t type,
                                          uint64_t prot)
{
    if (pages == 0)
        return nullptr;

    /* Lock everything before allocating anything */
    bool allocating_kernel = true;
    if (flags & VM_ADDRESS_USER)
        allocating_kernel = false;

    __vm_lock(allocating_kernel);

    struct vm_region *region = __vm_allocate_virt_region(flags, pages, type, prot);

    __vm_unlock(allocating_kernel);

    return region;
}

vm_region *vm_search(struct mm_address_space *mm, void *addr, size_t length)
{
    struct search_type
    {
        unsigned long base;
        size_t pages;
        struct bst_node node;
    } search;

    search.base = (unsigned long) addr & -PAGE_SIZE;
    search.pages = vm_size_to_pages(length);

    auto node = bst_search(
        &mm->region_tree, &search.node, [](struct bst_node *lhs_, struct bst_node *rhs_) -> int {
            auto lhs = container_of(lhs_, vm_region, tree_node);
            auto rhs = container_of(rhs_, search_type, node);

            if (check_for_overlap(lhs->base, lhs->base + (lhs->pages << PAGE_SHIFT) - 1, rhs->base,
                                  rhs->base + (rhs->pages << PAGE_SHIFT) - 1))
            {
                return 0;
            }
            else if (rhs->base > lhs->base)
                return 1;
            else
                return -1;
        });

    return node ? container_of(node, vm_region, tree_node) : nullptr;
}

bool vm_region_is_empty(void *addr, size_t length)
{
    struct mm_address_space *mm = get_current_address_space();
    return vm_search(mm, addr, length) == nullptr;
}

#define VM_CREATE_REGION_AT_DEBUG 0

struct vm_region *__vm_create_region_at(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
    bool reserving_kernel = is_higher_half(addr);
    struct vm_region *v = nullptr;

    if (!vm_region_is_empty(addr, pages << PAGE_SHIFT))
    {
#if VM_CREATE_REGION_AT_DEBUG
        sched_enable_preempt();
        printk("Failed to map %p - %lx\n", addr, (unsigned long) addr + (pages << PAGE_SHIFT));
        vm_print_umap();
        sched_disable_preempt();
#endif

        errno = EINVAL;
        return nullptr;
    }

    struct mm_address_space *mm =
        reserving_kernel ? &kernel_address_space : get_current_process()->get_aspace();

    if (!vm_test_vs_rlimit(mm, pages << PAGE_SHIFT))
    {
        return errno = ENOMEM, nullptr;
    }

    v = vm_reserve_region(mm, (unsigned long) addr, pages << PAGE_SHIFT);
    if (!v)
    {
        addr = nullptr;
        errno = ENOMEM;
        goto return_;
    }

    increment_vm_stat(mm, virtual_memory_size, pages << PAGE_SHIFT);

    v->base = (unsigned long) addr;
    v->pages = pages;
    v->type = type;
    v->rwx = prot;

return_:
    return v;
}

/**
 * @brief Creates a new vm region at a specified address.
 * Should only be used by core MM code.
 *
 * @param addr Address of the mapping.
 * @param pages Number of pages.
 * @param type Type of the mapping.
 * @param prot Protection flags.
 * @return The new vm_region, or NULL in case of failure (check errno).
 */
struct vm_region *vm_create_region_at(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
    bool reserving_kernel = is_higher_half(addr);
    struct vm_region *v = nullptr;

    __vm_lock(reserving_kernel);

    assert(prot & VM_USER && !reserving_kernel);
    v = __vm_create_region_at(addr, pages, type, prot);

    __vm_unlock(reserving_kernel);

    return v;
}

/**
 * @brief Finds a vm region.
 *
 * @param addr An address inside the region.
 * @return A pointer to the region, or NULL if it doesn't exist.
 */
struct vm_region *vm_find_region(void *addr)
{
    auto addrspace = (unsigned long) addr < kernel_address_space.start ? get_current_address_space()
                                                                       : &kernel_address_space;
    return vm_search(addrspace, addr, 2);
}

/**
 * @brief Creats a new address space.
 *
 * @param addr_space A pointer to the new address space.
 * @return 0 on success, negative on error.
 */
int vm_clone_as(mm_address_space *addr_space, mm_address_space *original)
{
    if (!original)
        original = get_current_address_space();
    if (!original)
        original = &kernel_address_space;
    return paging_clone_as(addr_space, original);
}

/**
 * @brief Remaps an entire vm_region.
 * Using flags, it remaps the entire vm_region by iterating through every page and
 * re-mapping it. If VM_FLUSH_RWX_VALID, rwx is a valid combination of permission
 * flags and rwx overrides the pre-existing permissions in the vm_region (used in COW fork).
 * Should only be used by MM code.
 *
 * @param mapping A pointer to the vm_region.
 * @param mm      A pointer to the destination mm_address_space.
 * @param flags Flag bitmask. Valid flags are (VM_FLUSH_RWX_VALID).
 * @param rwx If VM_FLUSH_RWX_VALID, rwx is a valid combination of permission flags.
 * @return 0 on success, negative error codes.
 */
int vm_flush_mapping(struct vm_region *mapping, struct mm_address_space *mm, unsigned int flags,
                     unsigned int rwx)
{
    struct vm_object *vmo = mapping->vmo;

    assert(vmo != nullptr);

    size_t nr_pages = mapping->pages;

    size_t off = mapping->offset;
    struct rb_itor it;
    it.node = nullptr;

    scoped_mutex g{vmo->page_lock};

    it.tree = vmo->pages;
    int mapping_rwx = flags & VM_FLUSH_RWX_VALID ? (int) rwx : mapping->rwx;

    bool node_valid = rb_itor_search_ge(&it, (void *) off);
    while (node_valid)
    {
        struct page *p = (page *) *rb_itor_datum(&it);
        size_t poff = (size_t) rb_itor_key(&it);

        if (poff >= off + (nr_pages << PAGE_SHIFT))
            break;
        unsigned long reg_off = poff - off;
        if (!__map_pages_to_vaddr(mm, (void *) (mapping->base + reg_off), page_to_phys(p),
                                  PAGE_SIZE, mapping_rwx))
            return -ENOMEM;

        node_valid = rb_itor_next(&it);
    }

    return 0;
}

/**
 * @brief Remaps an entire vm_region.
 * Using flags, it remaps the entire vm_region by iterating through every page and
 * re-mapping it. If VM_FLUSH_RWX_VALID, rwx is a valid combination of permission
 * flags and rwx overrides the pre-existing permissions in the vm_region (used in COW fork).
 * Should only be used by MM code.
 *
 * @param entry A pointer to the vm_region.
 * @param flags Flag bitmask. Valid flags are (VM_FLUSH_RWX_VALID).
 * @param rwx If VM_FLUSH_RWX_VALID, rwx is a valid combination of permission flags.
 * @return 0 on success, negative error codes.
 */
int vm_flush(struct vm_region *entry, unsigned int flags, unsigned int rwx)
{
#if DEBUG_VM_FLUSH
    printk("Has process? %s\n", p ? "true" : "false");
#endif
    return vm_flush_mapping(entry, entry->mm, flags, rwx);
}

struct fork_iteration
{
    struct mm_address_space *target_mm;
    bool success;
};

struct vm_object *find_forked_private_vmo(struct vm_object *old, struct mm_address_space *mm)
{
    scoped_mutex<false> g{mm->private_vmo_lock};

    struct vm_object *vmo = mm->vmo_head;
    struct vm_object *to_ret = nullptr;

    while (vmo)
    {
        if (vmo->forked_from == old)
        {
            to_ret = vmo;
            goto out;
        }
        vmo = vmo->next_private;
    }

out:
    return to_ret;
}

#define DEBUG_FORK_VM 0
static bool fork_vm_region(struct vm_region *region, struct fork_iteration *it)
{
    bool vmo_failure, is_private, using_shared_optimization, needs_to_fork_memory;
    unsigned int new_rwx;
    bool res;

    struct vm_region *new_region = vm_alloc_vmregion();
    if (!new_region)
    {
        goto ohno;
    }

    memcpy(new_region, region, sizeof(*region));

#if DEBUG_FORK_VM
    printk("Forking [%016lx, %016lx] perms %x\n", region->base,
           region->base + (region->pages << PAGE_SHIFT) - 1, region->rwx);
#endif
    bst_node_initialize(&new_region->tree_node);

    res = vm_insert_region(it->target_mm, new_region);

    assert(res == true);

    if (new_region->fd)
        fd_get(new_region->fd);

    vmo_failure = false;
    is_private = !is_mapping_shared(new_region);
    using_shared_optimization = vm_using_shared_optimization(new_region);
    needs_to_fork_memory = is_private && !using_shared_optimization;

    if (needs_to_fork_memory)
    {
        /* No need to ref the vmo since it was a new vmo created for us while forking. */
        new_region->vmo = find_forked_private_vmo(new_region->vmo, it->target_mm);
        assert(new_region->vmo != nullptr);
        vmo_assign_mapping(new_region->vmo, new_region);
        vmo_ref(new_region->vmo);
    }
    else
    {
        vmo_ref(new_region->vmo);
        vmo_assign_mapping(new_region->vmo, new_region);
    }

    if (vmo_failure)
    {
        vm_remove_region(it->target_mm, new_region);
        vm_free_vmregion(new_region);
        goto ohno;
    }

    new_region->mm = it->target_mm;

    /* If it's a private mapping, we're mapping it either COW if it's a writable mapping, or
     * just not writable if it's a a RO/R-X mapping. Therefore, we mask the VM_WRITE bit
     * out of the flush permissions, as to map things write-protected if it's a writable mapping.
     */

    new_rwx = is_private ? new_region->rwx & ~VM_WRITE : new_region->rwx;
    if (vm_flush(new_region, VM_FLUSH_RWX_VALID, new_rwx | VM_NOFLUSH) < 0)
    {
        /* Let the generic addr space destruction code handle this,
         * since there's everything's set now */
        goto ohno;
    }

    if (is_private && region->rwx & VM_WRITE)
    {
        /* If the region is writable and we're a private mapping, we'll need to
         * mark the original mapping as write-protected too, so the parent can also trigger COW
         * behaviour.
         */
        int st = vm_flush(region, VM_FLUSH_RWX_VALID, new_rwx);

        /* I don't even know how it should be possible to OOM changing protections
         * of mappings that already exist. TODO: BUT, is it a plausible thing and should we handle
         * it? */
        assert(st == 0);
    }
    return true;

ohno:
    it->success = false;
    return false;
}

void addr_space_delete(vm_region *region)
{

    do_vm_unmap((void *) region->base, region->pages);

    vm_region_destroy(region);
}

void tear_down_addr_space(struct mm_address_space *addr_space)
{
    /*
     * Note: We free the tree first in order to free any forked pages.
     * If we didn't we would leak some memory.
     */
    vm_region *entry;
    bst_for_every_entry_delete(&addr_space->region_tree, entry, vm_region, tree_node)
    {
        addr_space_delete(entry);
    }

    paging_free_page_tables(addr_space);
}

int vm_fork_private_vmos(struct mm_address_space *mm)
{
    struct mm_address_space *parent_mm = get_current_address_space();
    scoped_mutex<false> g{parent_mm->private_vmo_lock};

    struct vm_object *vmo = parent_mm->vmo_head;

    while (vmo)
    {
        struct vm_object *new_vmo = vmo_fork(vmo, false, nullptr);
        if (!new_vmo)
        {
            return -1;
        }

        new_vmo->refcount = 0;
        add_vmo_to_private_list(mm, new_vmo);

        vmo = vmo->next_private;
    }

    return 0;
}

/**
 * @brief Fork the current address space into a new address space.
 *
 * @param addr_space The new address space.
 * @return 0 on success, negative on error.
 */
int vm_fork_address_space(struct mm_address_space *addr_space)
{
    __vm_lock(false);

#if CONFIG_DEBUG_ADDRESS_SPACE_ACCT
    mmu_verify_address_space_accounting(get_current_address_space());
#endif
    if (vm_fork_private_vmos(addr_space) < 0)
    {
        __vm_unlock(false);
        return -1;
    }

    struct fork_iteration it = {};
    it.target_mm = addr_space;
    it.success = true;

    if (paging_fork_tables(addr_space) < 0)
    {
        __vm_unlock(false);
        return -1;
    }

    struct mm_address_space *current_mm = get_current_address_space();

    bst_root_initialize(&addr_space->region_tree);

    addr_space->resident_set_size = current_mm->resident_set_size;
    addr_space->shared_set_size = current_mm->shared_set_size;
    addr_space->virtual_memory_size = current_mm->virtual_memory_size;

    vm_region *entry;
    bst_for_every_entry(&current_mm->region_tree, entry, vm_region, tree_node)
    {
        if (!fork_vm_region(entry, &it))
        {
            tear_down_addr_space(addr_space);
            __vm_unlock(false);
            return -1;
        }
    }

    /* We add the old ones here because rss will only be incremented by pages that were newly
     * mapped, since the old page table entries were copied in.
     */
    addr_space->mmap_base = current_mm->mmap_base;
    addr_space->brk = current_mm->brk;
    addr_space->start = current_mm->start;
    addr_space->end = current_mm->end;

#if CONFIG_DEBUG_ADDRESS_SPACE_ACCT
    mmu_verify_address_space_accounting(addr_space);
#endif

    assert(addr_space->active_mask.is_empty());

    mutex_init(&addr_space->vm_lock);

    __vm_unlock(false);
    return 0;
}

/**
 * @brief Allocates a range of virtual memory for kernel purposes.
 * This memory is all prefaulted and cannot be demand paged nor paged out.
 *
 * @param pages The number of pages.
 * @param type The type of allocation.
 * @param perms The permissions on the allocation.
 * @return A pointer to the new allocation, or NULL with errno set on failure.
 */
void *vmalloc_sleep(size_t pages, int type, int perms)
{
    struct vm_region *vm = vm_allocate_virt_region(VM_KERNEL, pages, type, perms);
    if (!vm)
        return nullptr;

    struct vm_object *vmo = vmo_create_phys(pages << PAGE_SHIFT);
    if (!vmo)
    {
        vm_destroy_mappings((void *) vm->base, pages);
        return nullptr;
    }

    vmo_assign_mapping(vmo, vm);

    vm->vmo = vmo;

    if (vmo_prefault(vmo, pages << PAGE_SHIFT, 0) < 0)
    {
        /* FIXME: This code doesn't seem correct */
        vmo_remove_mapping(vmo, vm);
        vmo_unref(vmo);
        vm->vmo = nullptr;
        vm_destroy_mappings(vm, pages);
        return nullptr;
    }

    if (vm_flush(vm, VM_FLUSH_RWX_VALID, vm->rwx | VM_NOFLUSH) < 0)
    {
        /* FIXME: Same as above */
        vmo_remove_mapping(vmo, vm);
        vmo_unref(vmo);
        vm_destroy_mappings(vm, pages);
        return nullptr;
    }

#ifdef CONFIG_KASAN
    kasan_alloc_shadow(vm->base, pages << PAGE_SHIFT, true);
#endif
    return (void *) vm->base;
}

/**
 * @brief Frees a region of memory previously allocated by vmalloc.
 *
 * @param ptr A pointer to the allocation.
 * @param pages The number of pages it consists in.
 */
void vfree_sleep(void *ptr, size_t pages)
{
    vm_munmap(&kernel_address_space, ptr, pages << PAGE_SHIFT);
}

bool vm_may_merge_with_adj(vm_region *reg)
{
    // TODO: merging is broken right now
    return false;
#if 0
    auto prev_node = bst_prev(&reg->mm->region_tree, &reg->tree_node);

    if (!prev_node)
        return false;

    auto prev = container_of(prev_node, vm_region, tree_node);

    if (vmo_is_shared(prev->vmo))
        return false;

    return (false && prev->mapping_type == reg->mapping_type && reg->type == prev->type &&
            prev->base + (prev->pages << PAGE_SHIFT) == reg->base && prev->fd == reg->fd &&
            reg->fd == nullptr && reg->rwx == prev->rwx && !is_mapping_shared(reg) &&
            !is_file_backed(reg));
#endif
}

void vm_merge_with_prev(vm_region *reg)
{
    auto prev_node = bst_prev(&reg->mm->region_tree, &reg->tree_node);

    assert(prev_node);
    auto prev = container_of(prev_node, vm_region, tree_node);

#if 0
    printk("[%lx, %lx] + [%lx, %lx] =", prev->base, prev->base + (prev->pages << PAGE_SHIFT),
           reg->base, reg->base + (reg->pages << PAGE_SHIFT));
#endif
    prev->pages += reg->pages;
    auto oldsize = prev->vmo->size;
    prev->vmo->size = oldsize + (reg->pages << PAGE_SHIFT);
    // vmo_truncate(prev->vmo, oldsize + ((reg->pages + 200) << PAGE_SHIFT), 0);
    vm_remove_region(reg->mm, reg);
#if 0
    printk(" [%lx, %lx]\n", prev->base, prev->base + (prev->pages << PAGE_SHIFT));
    printk("vmo size %lx -> %lx\n", oldsize, prev->vmo->size);
#endif
    vm_free_vmregion(reg);
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
 * @return A pointer to the new memory mapping, or NULL if it failed (errno is set).
 */
void *vm_mmap(void *addr, size_t length, int prot, int flags, struct file *file, off_t off)
{
    int st = 0;
    struct vm_region *area = nullptr;
    bool is_file_mapping = file != nullptr;
    void *base = nullptr;

    struct mm_address_space *mm = get_current_address_space();

    /* We don't like this offset. */
    if (off & (PAGE_SIZE - 1))
        return errno = EINVAL, nullptr;

    scoped_mutex g{mm->vm_lock};

    /* Calculate the pages needed for the overall size */
    size_t pages = vm_size_to_pages(length);

    if (prot & (PROT_WRITE | PROT_EXEC))
        prot |= PROT_READ;

    int vm_prot = VM_USER | ((prot & PROT_READ) ? VM_READ : 0) |
                  ((prot & PROT_WRITE) ? VM_WRITE : 0) | ((prot & PROT_EXEC) ? VM_EXEC : 0);

    /* Sanitize the address */
    if (is_higher_half(addr) || (unsigned long) addr & (PAGE_SIZE - 1))
    {
        if (flags & MAP_FIXED)
        {
            st = -ENOMEM;
            goto out_error;
        }
        else
            addr = nullptr;
    }

    if (!addr)
    {
        if (flags & MAP_FIXED)
        {
            st = -ENOMEM;
            goto out_error;
        }
        /* Specified by POSIX, if addr == nullptr, guess an address */
        area = __vm_allocate_virt_region(VM_ADDRESS_USER, pages, VM_TYPE_SHARED, vm_prot);
    }
    else
    {
        if (flags & MAP_FIXED)
        {
            vm_unmap_every_region_in_range(mm, (unsigned long) addr, pages << PAGE_SHIFT);
        }

        area = __vm_create_region_at(addr, pages, VM_TYPE_REGULAR, vm_prot);
        if (!area)
        {
            if (flags & MAP_FIXED)
            {
                st = -ENOMEM;
                goto out_error;
            }

            area = __vm_allocate_virt_region(VM_ADDRESS_USER, pages, VM_TYPE_REGULAR, vm_prot);
        }
    }

    if (!area)
    {
        st = -ENOMEM;
        goto out_error;
    }

    if (flags & MAP_SHARED)
        area->mapping_type = MAP_SHARED;
    else
        area->mapping_type = MAP_PRIVATE;

    if (is_file_mapping)
    {
        // printk("Mapping off %lx, size %lx, prots %x\n", off, length, prot);

        /* Set additional meta-data */

        area->type = VM_TYPE_FILE_BACKED;

        area->offset = off;
        area->fd = file;
        fd_get(file);

        struct inode *ino = file->f_ino;

        if (ino->i_type == VFS_TYPE_BLOCK_DEVICE || ino->i_type == VFS_TYPE_CHAR_DEVICE)
        {
            if (!ino->i_fops->mmap)
            {
                __vm_munmap(mm, (void *) area->base, pages << PAGE_SHIFT);
                return errno = ENODEV, nullptr;
            }

            void *ret = ino->i_fops->mmap(area, file);

            if (ret)
                inode_update_atime(ino);
            else
                __vm_munmap(mm, (void *) area->base, pages << PAGE_SHIFT);

            if (ret)
                goto out;

            return ret;
        }
    }
    else if (vm_may_merge_with_adj(area))
    {
        base = (void *) area->base;
        vm_merge_with_prev(area);
        return base;
    }

    if (vm_region_setup_backing(area, pages, !(flags & MAP_ANONYMOUS)) < 0)
    {
        __vm_munmap(mm, (void *) area->base, pages << PAGE_SHIFT);
        return errno = ENOMEM, nullptr;
    }

out:
    if (flags & MAP_SHARED)
        increment_vm_stat(mm, shared_set_size, pages << PAGE_SHIFT);

    base = (void *) area->base;

    return base;

out_error:
    return errno = -st, nullptr;
}

void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t off)
{
    int error = 0;

    struct file *file = nullptr;
    void *ret = nullptr;
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

    if (ret == nullptr)
    {
        ret = (void *) (unsigned long) -errno;
    }

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
    // printk("munmap [%p, %lx]\n", addr, (unsigned long) addr + length - 1);

    if (is_higher_half(addr))
        return -EINVAL;

    size_t pages = vm_size_to_pages(length);

    if ((unsigned long) addr & (PAGE_SIZE - 1))
        return -EINVAL;

    struct mm_address_space *mm = get_current_process()->get_aspace();

    int ret = vm_munmap(mm, addr, pages << PAGE_SHIFT);

    return ret;
}

void vm_copy_region(const struct vm_region *source, struct vm_region *dest)
{
    dest->fd = source->fd;
    if (dest->fd)
    {
        /*struct file *ino = dest->fd->f_ino;
        if(source->mapping_type == MAP_SHARED && inode_requires_wb(ino))
            writeback_add_region(dest);*/
        fd_get(dest->fd);
    }

    dest->flags = source->flags;
    dest->rwx = source->rwx;
    dest->mapping_type = source->mapping_type;
    dest->offset = source->offset;
    dest->mm = source->mm;
    dest->vmo = source->vmo;
    vmo_assign_mapping(dest->vmo, dest);
    vmo_ref(dest->vmo);
    dest->type = source->type;
}

struct vm_region *vm_split_region(struct mm_address_space *as, struct vm_region *region,
                                  unsigned long addr, size_t size, size_t *pto_shave_off)
{
    size_t region_size = region->pages << PAGE_SHIFT;

    size_t to_shave_off = 0;
    if (region->base == addr)
    {
        to_shave_off = size < region_size ? size : region_size;
        *pto_shave_off = to_shave_off;

        if (to_shave_off != region_size)
        {
            vm_remove_region(as, region);

            off_t old_off = region->offset;

            region->base += to_shave_off;
            region->pages -= to_shave_off >> PAGE_SHIFT;
            region->offset += to_shave_off;
            if (vm_add_region(as, region) < 0)
            {
                return errno = ENOMEM, nullptr;
            }

            struct vm_region *reg = vm_reserve_region(as, addr, to_shave_off);

            if (!reg)
            {
                return errno = ENOMEM, nullptr;
            }

            /* Essentially, we create a carbon
             * copy of the region and increment/decrement some values */
            vm_copy_region(region, reg);
            reg->base = addr;
            reg->pages = to_shave_off >> PAGE_SHIFT;

            /* Also, set the offset of the old region */
            reg->offset = old_off;
            return reg;
        }
        else
        {
            return region;
        }
    }
    else if (region->base < addr)
    {
        unsigned long offset = addr - region->base;
        unsigned long remainder = region_size - offset;
        to_shave_off = size < remainder ? size : remainder;
        *pto_shave_off = to_shave_off;

        if (to_shave_off != remainder)
        {
            vm_remove_region(as, region);

            unsigned long second_region_start = addr + to_shave_off;
            unsigned long second_region_size = remainder - to_shave_off;

            struct vm_region *new_region =
                vm_reserve_region(as, second_region_start, second_region_size);

            if (!new_region)
            {
                return errno = ENOMEM, nullptr;
            }

            vm_copy_region(region, new_region);
            new_region->offset += offset + to_shave_off;

            struct vm_region *to_ret = vm_reserve_region(as, addr, to_shave_off);
            if (!to_ret)
            {
                vm_remove_region(as, new_region);
                return errno = ENOMEM, nullptr;
            }

            vm_copy_region(region, to_ret);
            to_ret->offset += offset;

            /* The original region's size is offset */
            region->pages = offset >> PAGE_SHIFT;

            /* FIXME: it's not clear what we should do on OOM cases
             * This code and munmap's code is riddled with these things. */
            (void) vm_add_region(as, region);

            return to_ret;
        }
        else
        {
            region->pages -= to_shave_off >> PAGE_SHIFT;

            struct vm_region *to_ret = vm_reserve_region(as, addr, to_shave_off);
            if (!to_ret)
            {
                return errno = ENOMEM, nullptr;
            }

            vm_copy_region(region, to_ret);
            to_ret->offset += offset;

            return to_ret;
        }
    }

    __builtin_unreachable();
}

int vm_mprotect_in_region(struct mm_address_space *as, struct vm_region *region, unsigned long addr,
                          size_t size, int *pprot, size_t *pto_shave_off)
{
    int prot = *pprot;
    // printk("mprotect %lx - %lx, prot %x\n", addr, addr + size, prot);

    struct vm_region *new_region = vm_split_region(as, region, addr, size, pto_shave_off);
    if (!new_region)
        return -ENOMEM;

    bool marking_write = (prot & VM_WRITE) && !(new_region->rwx & VM_WRITE);

    new_region->rwx = prot;

    if (marking_write && (vm_mapping_is_cow(region) || vm_mapping_requires_write_protect(region)))
    {
        /* If we're a COW mapping or some kind of mapping that requires write-protection,
         * we can't change the pages' permissions to allow VM_WRITE
         */
        *pprot &= ~VM_WRITE;
    }

    return 0;
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
{
    unsigned long addr = (unsigned long) __addr;
    unsigned long limit = addr + size;

    scoped_mutex g{as->vm_lock};

    while (addr < limit)
    {
        struct vm_region *region = vm_search(as, __addr, size);
        if (!region)
            return -EINVAL;

        if (region->mapping_type == MAP_SHARED && region->fd && prot & PROT_WRITE)
        {
            /* Block the mapping if we're trying to mprotect a shared mapping to PROT_WRITE while
             * not having the necessary perms on the file.
             */

            struct file *file = region->fd;
            bool fd_has_write = fd_may_access(file, FILE_ACCESS_WRITE);

            if (!fd_has_write)
                return -EACCES;
        }

        size_t to_shave_off = 0;
        int old_prots = region->rwx;
        int new_prots = prot;

        int st = vm_mprotect_in_region(as, region, addr, size, &new_prots, &to_shave_off);

        if (st < 0)
            return st;

        vm_do_mmu_mprotect(as, (void *) addr, to_shave_off >> PAGE_SHIFT, old_prots, new_prots);

        addr += to_shave_off;
        size -= to_shave_off;
    }

    return 0;
}

int sys_mprotect(void *addr, size_t len, int prot)
{
    if (is_higher_half(addr))
        return -EINVAL;
    struct vm_region *area = nullptr;

    if (!(area = vm_find_region(addr)))
    {
        return -EINVAL;
    }

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

    struct process *p = get_current_process();
    // vm_print_umap();
    int st = vm_mprotect(p->address_space.get(), addr, len, vm_prot);
    // vm_print_umap();
    // while(true) {}
    return st;
}

int vm_expand_brk(size_t nr_pages);

int do_inc_brk(void *oldbrk, void *newbrk)
{
    void *oldpage = page_align_up(oldbrk);
    void *newpage = page_align_up(newbrk);

    size_t pages = ((uintptr_t) newpage - (uintptr_t) oldpage) / PAGE_SIZE;

    if (pages > 0)
    {
        return vm_expand_brk(pages);
    }

    return 0;
}

uint64_t sys_brk(void *newbrk)
{
    mm_address_space *as = get_current_address_space();

    scoped_mutex g{as->vm_lock};

    if (newbrk == nullptr)
    {
        uint64_t ret = (uint64_t) as->brk;
        return ret;
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
        if (do_inc_brk(old_brk, newbrk) < 0)
        {
            return -ENOMEM;
        }

        as->brk = newbrk;
    }

    uint64_t ret = (uint64_t) as->brk;
    return ret;
}

static bool vm_print(const void *key, void *datum, void *user_data)
{
    struct vm_region *region = (vm_region *) datum;
    bool x = region->rwx & VM_EXEC;
    bool w = region->rwx & VM_WRITE;
    bool file_backed = is_file_backed(region);
    struct file *fd = region->fd;

    printk("(key %p) [%016lx - %016lx] : %s%s%s\n", key, region->base,
           region->base + (region->pages << PAGE_SHIFT), "R", w ? "W" : "-", x ? "X" : "-");
    printk("vmo %p mapped at offset %lx", region->vmo, region->offset);
    if (file_backed)
        printk(" - file backed ino %lu\n", fd->f_ino->i_inode);
    else
        printk("\n");

    return true;
}

/**
 * @brief Traverses the kernel's memory map and prints information.
 *
 */
void vm_print_map(void)
{
    // rb_tree_traverse(kernel_address_space.area_tree, vm_print, nullptr);
}

/**
 * @brief Traverses the current process's memory map and prints information.
 *
 */
void vm_print_umap()
{
    // rb_tree_traverse(get_current_address_space()->area_tree, vm_print, nullptr);
}

/**
 * @brief Map a specific number of pages onto a virtual address.
 * Should only be used by MM code since it does not touch vm_regions, only
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
    return __map_pages_to_vaddr(nullptr, virt, phys, size, flags);
}

struct vm_pf_context
{
    /* The vm region in question */
    struct vm_region *entry;
    /* This fault's info */
    struct fault_info *info;
    /* vpage - fault_address but page aligned */
    unsigned long vpage;
    /* Page permissions - is prefilled by calling code */
    int page_rwx;
    /* Mapping info if page was present */
    unsigned long mapping_info;
    /* The to-be-mapped page - filled by called code */
    struct page *page;
};

int vmo_error_to_vm_error(vmo_status_t st)
{
    switch (st)
    {
        case VMO_STATUS_OK:
            return VM_OK;
        case VMO_STATUS_OUT_OF_MEM:
            return VM_SIGSEGV;
        default:
            return VM_SIGBUS;
    }
}

vmo_status_t vm_pf_get_page_from_vmo(struct vm_pf_context *ctx)
{
    struct vm_region *entry = ctx->entry;
    size_t vmo_off = (ctx->vpage - entry->base) + entry->offset;

    return vmo_get(entry->vmo, vmo_off, VMO_GET_MAY_POPULATE, &ctx->page);
}

int vm_handle_non_present_wp(struct fault_info *info, struct vm_pf_context *ctx)
{
    struct vm_region *entry = ctx->entry;

    assert(info->read ^ info->write);
    if (!info->write)
    {
        /* If we'll need to wp, write-protect */
        ctx->page_rwx &= ~VM_WRITE;
        if (vm_mapping_is_anon(entry))
        {
            ctx->page = vm_zero_page;
        }
    }
    else
    {
        if (vm_mapping_requires_wb(entry))
        {
            /* else handle it differently(we'll need) */
            vmo_status_t st = vm_pf_get_page_from_vmo(ctx);

            if (st != VMO_STATUS_OK)
            {
                info->signal = vmo_error_to_vm_error(st);
                return -1;
            }

            pagecache_dirty_block(ctx->page->cache);
        }
        else if (vm_mapping_is_anon(entry))
        {
            /* This is done in vm_pf_get_page_from_vmo */
        }
    }

    return 0;
}

bool vm_mapping_is_cow(struct vm_region *entry)
{
    return entry->mapping_type == MAP_PRIVATE;
}

int vm_handle_non_present_copy_on_write(struct fault_info *info, struct vm_pf_context *ctx)
{
    bool is_write = info->write;

    /* Let the vm_pf_get_page_from_vmo() do that */
    if (is_write)
        return 0;

    struct vm_region *entry = ctx->entry;
    size_t vmo_off = (ctx->vpage - entry->base) + entry->offset;

    struct vm_object *vmo = entry->vmo;

    /* If we don't have a COW clone, this means we're an anon mapping and we're just looking to
     * COW-map the zero page
     */
    if (!vmo->cow_clone)
    {
        assert(*(volatile int *) PAGE_TO_VIRT(vm_zero_page) == 0);
        page_ref(vm_zero_page);
        page_ref(vm_zero_page);
        vmo_add_page(vmo_off, vm_zero_page, vmo);
        ctx->page = vm_zero_page;
        ctx->page_rwx &= ~VM_WRITE;
        return 0;
    }

#if 0
	printk("Vmo off: %lx\n", vmo_off);
	printk("Faulting %lx in\n", ctx->vpage);
#endif

    vmo_status_t st = vmo_get_cow_page(vmo, vmo_off, &ctx->page);
    if (st != VMO_STATUS_OK)
    {
        ctx->info->signal = vmo_error_to_vm_error(st);
        return -1;
    }

    ctx->page_rwx &= ~VM_WRITE;

    return 0;
}

int vm_handle_non_present_pf(struct vm_pf_context *ctx)
{
    struct vm_region *entry = ctx->entry;
    struct fault_info *info = ctx->info;

    if (vm_mapping_requires_write_protect(entry))
    {
        if (vm_handle_non_present_wp(info, ctx) < 0)
            return -1;
    }
    else if (vm_mapping_is_cow(entry))
    {
        if (vm_handle_non_present_copy_on_write(info, ctx) < 0)
            return -1;
    }

    /* If page wasn't set before by other fault handling code, just fetch from the vmo */
    if (ctx->page == nullptr)
    {
        vmo_status_t st = vm_pf_get_page_from_vmo(ctx);
        if (st != VMO_STATUS_OK)
        {
            info->signal = vmo_error_to_vm_error(st);
            return -1;
        }
    }

    if (!map_pages_to_vaddr((void *) ctx->vpage, page_to_phys(ctx->page), PAGE_SIZE,
                            ctx->page_rwx | VM_NOFLUSH))
    {
        page_unpin(ctx->page);
        info->signal = VM_SIGSEGV;
        return -1;
    }

    page_unpin(ctx->page);

    return 0;
}

int vm_handle_write_wb(struct vm_pf_context *ctx)
{
    unsigned long paddr = MAPPING_INFO_PADDR(ctx->mapping_info);
    struct page *p = phys_to_page(paddr);
    int st = 0;

    if ((st = p->cache->node->i_fops->prepare_write(p->cache->node, p, 0, p->cache->offset,
                                                    PAGE_SIZE) < 0))
    {
        return st;
    }

    pagecache_dirty_block(p->cache);

    // Note: We and-out VM_WRITE so do_mmu_mprotect does the proper thing (un-wp's)
    vm_do_mmu_mprotect(ctx->entry->mm, (void *) ctx->vpage, 1, ctx->entry->rwx & ~VM_WRITE,
                       ctx->page_rwx);

    return 0;
}

#include <onyx/dentry.h>

int vm_handle_present_cow(struct vm_pf_context *ctx)
{
    struct vm_object *vmo = ctx->entry->vmo;
    struct fault_info *info = ctx->info;

    struct vm_region *entry = ctx->entry;
    size_t vmo_off = (ctx->vpage - entry->base) + entry->offset;

#if 0
    printk("Re-mapping COW'd page %lx with perms %x\n", ctx->vpage, ctx->page_rwx);
    printk("fd: %p", entry->fd);

    if (entry->fd)
        printk(" (%s)\n", entry->fd->f_dentry->d_name);
    else
        printk("\n");
#endif

    struct page *new_page = vmo_cow_on_page(vmo, vmo_off);
    if (!new_page)
    {
        info->signal = VM_SIGSEGV;
        return -1;
    }

    if (!map_pages_to_vaddr((void *) ctx->vpage, page_to_phys(new_page), PAGE_SIZE, ctx->page_rwx))
    {
        page_unpin(new_page);
        info->signal = VM_SIGSEGV;
        return -1;
    }

    page_unpin(new_page);

    return 0;
}

int vm_handle_present_pf(struct vm_pf_context *ctx)
{
    struct vm_region *entry = ctx->entry;
    struct fault_info *info = ctx->info;
#if 0
	printk("Handling present PF at %lx %s%s%s\n", ctx->info->fault_address,
		ctx->info->write ? "W" : "-", ctx->info->read ? "R" : "-", ctx->info->exec ? "X" : "-");
#endif

    if (info->write & !(ctx->mapping_info & PAGE_WRITABLE))
    {
        if (vm_mapping_requires_wb(entry))
        {
            // printk("writeback!\n");
            return vm_handle_write_wb(ctx);
        }
        else if (vm_mapping_is_cow(entry))
        {
            // printk("C O W'ing page %lx, file backed: %s, pid %d\n", ctx->vpage, entry->fd ? "yes"
            // : "no", get_current_process()->pid);
            if (vm_handle_present_cow(ctx) < 0)
                return -1;
        }
        else
        {
            panic("Strange case inside vm_handle_present_pf");
        }
    }

    return 0;
}

int __vm_handle_pf(struct vm_region *entry, struct fault_info *info)
{
    assert(entry->vmo != nullptr);
    struct vm_pf_context context;
    context.entry = entry;
    context.info = info;
    context.vpage = info->fault_address & -PAGE_SIZE;
    context.page = nullptr;
    context.page_rwx = entry->rwx;
    context.mapping_info = get_mapping_info((void *) context.vpage);

#if 0
	struct process *p = get_current_process();

	printk("fault on address %lx, page %lx, "
	  " present %s, process %d (%s)\n", context.info->fault_address,
	  context.vpage, context.mapping_info & PAGE_PRESENT ? "true" : "false",
	  p->pid, p->cmd_line);
#endif

    if (context.mapping_info & PAGE_PRESENT)
    {
        if (vm_handle_present_pf(&context) < 0)
            return -1;
    }
    else
    {
        if (vm_handle_non_present_pf(&context) < 0)
            return -1;
    }

    // printk("elapsed: %lu ns\n", end - start);
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

    if (sched_is_preemption_disabled())
        panic("Page fault while preemption was disabled\n");
    if (irq_is_disabled())
        panic("Page fault while IRQs were disabled\n");

    /* Surrender immediately if there's no user address space or the fault was inside vm code */
    if (!as || mutex_holds_lock(&as->vm_lock))
    {
        info->signal = VM_SIGSEGV;
        return -1;
    }

    scoped_mutex g{as->vm_lock};

    struct vm_region *entry = vm_find_region((void *) info->fault_address);
    if (!entry)
    {
        struct thread *ct = get_current_thread();
        if (ct && info->user)
        {
            struct process *current = get_current_process();
            printk("Curr thread: %p\n", ct);
            const char *str;
            if (info->write)
                str = "write";
            else if (info->exec)
                str = "exec";
            else
                str = "read";
            printk("Page fault at %lx, %s, ip %lx, process name %s\n", info->fault_address, str,
                   info->ip, current ? current->cmd_line.c_str() : "(kernel)");
#if 0
            vm_print_umap();
            panic("pid %ld page fault", current->pid_);
#endif
        }

        info->signal = VM_SIGSEGV;
        return -1;
    }

    info->error_info = VM_BAD_PERMISSIONS;

    if (info->write && !(entry->rwx & VM_WRITE))
        return -1;
    if (info->exec && !(entry->rwx & VM_EXEC))
        return -1;
    if (info->user && !(entry->rwx & VM_USER))
        return -1;
    if (info->read && !(entry->rwx & VM_READ))
        return -1;

    info->error_info = 0;

    __sync_add_and_fetch(&as->page_faults, 1);

    int ret = __vm_handle_pf(entry, info);

    return ret;
}

static void vm_destroy_area(vm_region *region)
{
    vm_mmu_unmap(region->mm, (void *) region->base, region->pages);

    decrement_vm_stat(region->mm, virtual_memory_size, region->pages << PAGE_SHIFT);

    if (is_mapping_shared(region))
    {
        decrement_vm_stat(region->mm, shared_set_size, region->pages << PAGE_SHIFT);
    }

    vm_region_destroy(region);
}

/**
 * @brief Destroys an address space.
 *
 * @param mm A pointer to a valid mm_address_space.
 */
void vm_destroy_addr_space(struct mm_address_space *mm)
{
    bool free_pgd = true;

    /* First, iterate through the rb tree and free/unmap stuff */
    scoped_mutex g{mm->vm_lock};

    vm_region *entry;

    bst_for_every_entry_delete(&mm->region_tree, entry, vm_region, tree_node)
    {
        vm_destroy_area(entry);
    }

    assert(mm->resident_set_size == 0);
    assert(mm->shared_set_size == 0);
    assert(mm->virtual_memory_size == 0);
    assert(mm->page_tables_size == PAGE_SIZE);

    /* We're going to swap our address space to init's, and free our own */
    /* Note that we use mm explicitly, but switch to current->address_space explicitly.
     * This is because vm_destroy_addr_space is called when we need to destroy
     * an exec state (i.e an execve failure).
     */
    void *own_addrspace = vm_get_pgd(&mm->arch_mmu);

    if (own_addrspace == vm_get_fallback_pgd())
    {
        /* If init is deciding to exec without forking, don't free the fallback pgd! */
        free_pgd = false;
    }

    struct arch_mm_address_space old_arch_mmu;
    vm_set_pgd(&old_arch_mmu, own_addrspace);

    if (free_pgd)
        vm_free_arch_mmu(&old_arch_mmu);
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
    /* First write the lowest addresses, then the middle address, and then the higher addresses */
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

    if (c == '2' || c == '3')
        dentry_trim_caches();

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

    sysfs_add(&vm_obj, nullptr);
}

char *strcpy_from_user(const char *uptr)
{
    ssize_t len = strlen_user(uptr);
    if (len < 0)
    {
        errno = EFAULT;
        return nullptr;
    }

    char *buf = (char *) malloc(len + 1);
    if (!buf)
        return nullptr;
    buf[len] = '\0';

    if (copy_from_user(buf, uptr, len) < 0)
    {
        free(buf);
        errno = EFAULT;
        return nullptr;
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
    kstacks_addr += new_kernel_space_base;
    heap_addr += new_kernel_space_base;
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
        struct process *current = get_current_process();
        printf("%s at %016lx at ip %lx in process %u(%s)\n",
               info->signal == SIGSEGV ? "SEGV" : "SIGBUS", info->fault_address, info->ip,
               current->get_pid(), current->cmd_line.c_str());
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
        kernel_tkill(info->signal, get_current_thread(), SIGNAL_FORCE, &sinfo);
    }
    else
    {
        panic("Kernel fatal segfault accessing %016lx at ip %lx\n", info->fault_address, info->ip);
    }
}

/**
 * @brief Map a given VMO.

 * @param flags Flags for the allocation (VM_KERNEL, VM_ADDRESS_USER).
 * @param type Type of the vm region; this affects the placement.
 * @param pages Number of pages required.
 * @param prot Protection of the vm region (VM_WRITE, NOEXEC, etc).
 * @param vmo  A pointer to the backing vm object.
 *
 * @return A pointer to the allocated virtual address, or NULL.
 */
void *vm_map_vmo(size_t flags, uint32_t type, size_t pages, size_t prot, vm_object *vmo)
{
    bool kernel = !(flags & VM_ADDRESS_USER);
    struct mm_address_space *mm = kernel ? &kernel_address_space : get_current_address_space();

    scoped_mutex g{mm->vm_lock};

    struct vm_region *reg = __vm_allocate_virt_region(flags, pages, type, prot);
    if (!reg)
        return nullptr;

    vmo_ref(vmo);

    reg->vmo = vmo;
    vmo_assign_mapping(vmo, reg);
    reg->mapping_type = MAP_SHARED;

    increment_vm_stat(mm, shared_set_size, pages << PAGE_SHIFT);

    if (kernel)
    {
        if (vmo->type == VMO_ANON && vmo_prefault(reg->vmo, pages << PAGE_SHIFT, 0) < 0)
        {
            __vm_munmap(&kernel_address_space, (void *) reg->base, pages << PAGE_SHIFT);
            return nullptr;
        }

        if (vm_flush(reg, VM_FLUSH_RWX_VALID, reg->rwx | VM_NOFLUSH) < 0)
        {
            __vm_munmap(&kernel_address_space, (void *) reg->base, pages << PAGE_SHIFT);
            return nullptr;
        }

#ifdef CONFIG_KASAN
        kasan_alloc_shadow(reg->base, pages << PAGE_SHIFT, true);
#endif
    }

    return (void *) reg->base;
}

vmo_status_t vm_commit_private(struct vm_object *vmo, size_t off, struct page **ppage)
{
    struct page *p = alloc_page(0);
    if (!p)
        return VMO_STATUS_OUT_OF_MEM;
    p->priv = 0;

    struct inode *ino = vmo->ino;
    off_t file_off = (off_t) vmo->priv;

    // printk("commit %lx\n", off + file_off);
    unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
    assert(ino->i_fops->readpage != nullptr);
    ssize_t read = ino->i_fops->readpage(p, off + file_off, ino);

    thread_change_addr_limit(old);

    if (read < 0)
    {
        free_page(p);
        return VMO_STATUS_BUS_ERROR;
    }

    *ppage = p;

    return VMO_STATUS_OK;
}

void add_vmo_to_private_list(struct mm_address_space *mm, struct vm_object *vmo)
{
    scoped_mutex<false> g{mm->private_vmo_lock};

    if (!mm->vmo_head)
    {
        mm->vmo_head = mm->vmo_tail = vmo;
        vmo->prev_private = vmo->next_private = nullptr;
    }
    else
    {
        struct vm_object *old_tail = mm->vmo_tail;
        old_tail->next_private = vmo;
        vmo->prev_private = old_tail;
        vmo->next_private = nullptr;
        mm->vmo_tail = vmo;
    }
}

void remove_vmo_from_private_list(struct mm_address_space *mm, struct vm_object *vmo)
{
    scoped_mutex<false> g{mm->private_vmo_lock};

    bool is_head = vmo->prev_private == nullptr;
    bool is_tail = vmo->next_private == nullptr;

    if (is_head && is_tail)
        mm->vmo_head = mm->vmo_tail = nullptr;
    else if (is_head)
    {
        mm->vmo_head = vmo->next_private;
        if (mm->vmo_head)
            mm->vmo_head->prev_private = nullptr;
    }
    else if (is_tail)
    {
        mm->vmo_tail = vmo->prev_private;
        if (mm->vmo_tail)
            mm->vmo_tail->next_private = nullptr;
    }
    else
    {
        vmo->prev_private->next_private = vmo->next_private;
        vmo->next_private->prev_private = vmo->prev_private;
    }
}

bool vm_using_shared_optimization(struct vm_region *region)
{
    return region->flags & VM_USING_MAP_SHARED_OPT;
}

const struct vm_object_ops vm_private_file_map_ops = {.commit = vm_commit_private};

/**
 * @brief Sets up backing for a newly-mmaped region.
 *
 * @param region A pointer to a vm_region.
 * @param pages The size of the region, in pages.
 * @param is_file_backed True if file backed.
 * @return 0 on success, negative for errors.
 */
int vm_region_setup_backing(struct vm_region *region, size_t pages, bool is_file_backed)
{
    bool is_shared = is_mapping_shared(region);
    bool is_kernel = is_higher_half((void *) region->base);

    struct vm_object *vmo;

    if (is_file_backed && is_shared)
    {
        struct inode *ino = region->fd->f_ino;

        assert(ino->i_pages != nullptr);
        vmo_ref(ino->i_pages);
        vmo = ino->i_pages;
    }
    else if (is_file_backed && !is_shared)
    {
        /* Alright, we're using COW to fault stuff in */
        /* store the offset in vmo->priv */
        vmo = vmo_create(pages * PAGE_SIZE, (void *) region->offset);
        if (!vmo)
            return -1;
        vmo->ino = region->fd->f_ino;
        vmo->ops = &vm_private_file_map_ops;
        vmo_do_cow(vmo, region->fd->f_ino->i_pages);

        region->offset = 0;
    }
    else
    {
        vmo = vmo_create_phys(pages * PAGE_SIZE);

        if (!vmo)
            return -1;
        vmo->type = VMO_ANON;
    }

    vmo_assign_mapping(vmo, region);

    if (!is_shared && !is_kernel)
    {
        struct mm_address_space *mm = get_current_process()->get_aspace();

        add_vmo_to_private_list(mm, vmo);
    }

    assert(region->vmo == nullptr);
    region->vmo = vmo;
    return 0;
}

/**
 * @brief Determines if a mapping is shared.
 *
 * @param region A pointer to the vm_region.
 * @return True if shared, false if not.
 */
bool is_mapping_shared(struct vm_region *region)
{
    return region->mapping_type == MAP_SHARED;
}

/**
 * @brief Determines if a mapping is file backed.
 *
 * @param region A pointer to the vm_region.
 * @return True if file backed, false if not.
 */
bool is_file_backed(struct vm_region *region)
{
    return region->type == VM_TYPE_FILE_BACKED;
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
{
    struct vm_region *entry =
        vm_allocate_virt_region(VM_KERNEL, vm_size_to_pages(size), VM_TYPE_REGULAR, prot);
    if (!entry)
        return nullptr;
    void *vaddr = (void *) entry->base;

    uintptr_t u = (uintptr_t) vaddr;
    while (pl != nullptr)
    {
        if (!map_pages_to_vaddr((void *) u, page_to_phys(pl), PAGE_SIZE, prot))
        {
            vm_destroy_mappings(vaddr, vm_size_to_pages(size));
            return nullptr;
        }

        pl = pl->next_un.next_allocation;
        u += PAGE_SIZE;
    }

    return vaddr;
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

    assert(mm->active_mask.is_empty() == true);

    mutex_init(&mm->vm_lock);

    bst_root_initialize(&mm->region_tree);

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
                      MAP_PRIVATE | MAP_FIXED | MAP_ANON, nullptr, 0);

    if (!mm->brk)
    {
        return -ENOMEM;
    }

    return 0;
}

void validate_free(void *p)
{
    unsigned long ptr = (unsigned long) p;

    assert(ptr >= heap_addr);
    assert(ptr <= heap_addr + heap_size);
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

void vm_remove_region(struct mm_address_space *as, struct vm_region *region)
{
    MUST_HOLD_MUTEX(&as->vm_lock);

    bst_delete(&as->region_tree, &region->tree_node);
}

int vm_add_region(struct mm_address_space *as, struct vm_region *region)
{
    MUST_HOLD_MUTEX(&as->vm_lock);

    return vm_insert_region(as, region);
}

int __vm_munmap(struct mm_address_space *as, void *__addr, size_t size)
{
    unsigned long aligned_start = (unsigned long) __addr & -PAGE_SIZE;
    unsigned long limit = ALIGN_TO(((unsigned long) __addr) + size, PAGE_SIZE);
    size = limit - aligned_start;
    // printk("munmap [%016lx, %016lx]\n", addr, limit - 1);

    MUST_HOLD_MUTEX(&as->vm_lock);

    size_t found = 0;

    while (true)
    {
        struct vm_region *region = vm_search(as, (void *) aligned_start, size);
        if (!region)
        {
            return found ? 0 : -EINVAL;
        }

        found++;

        // printk("Looking at region [%016lx, %016lx]\n", region->base,
        //        region->base + (region->pages << PAGE_SHIFT) - 1);

        bool is_shared = is_mapping_shared(region);

        unsigned long reg_len = region->pages << PAGE_SHIFT;
        unsigned long addr = region->base < aligned_start ? aligned_start : region->base;
        unsigned long to_unmap = limit - addr < reg_len ? limit - addr : reg_len;

        size_t pages_to_unmap = vm_size_to_pages(to_unmap);

        vm_mmu_unmap(region->mm, (void *) addr, pages_to_unmap);

        size_t region_size = region->pages << PAGE_SHIFT;

        size_t to_shave_off = 0;
        if (region->base == addr)
        {
            to_shave_off = size < region_size ? size : region_size;

            if (to_shave_off != region_size)
            {
                /* If we're shaving off from the front, we'll need to adjust
                 * both the base, the size *and* the mapping's offset in relation to the VMO.
                 * TODO: Punch a whole through anonymous VMOs.
                 */
                region->base += to_shave_off;
                region->pages -= to_shave_off >> PAGE_SHIFT;
                region->offset += to_shave_off;
            }
            else
            {
                vm_remove_region(as, region);
                vm_region_destroy(region);
            }
        }
        else if (region->base < addr)
        {
            unsigned long offset = addr - region->base;
            unsigned long remainder = region_size - offset;
            to_shave_off = size < remainder ? size : remainder;

            if (to_shave_off != remainder)
            {
                /* The original region's size is offset */
                region->pages = offset >> PAGE_SHIFT;

                unsigned long second_region_start = addr + to_shave_off;
                unsigned long second_region_size = remainder - to_shave_off;

                struct vm_region *new_region =
                    vm_reserve_region(as, second_region_start, second_region_size);

                if (!new_region)
                {
                    return -ENOMEM;
                }

                new_region->rwx = region->rwx;

                if (region->fd)
                {
                    fd_get(region->fd);
                    new_region->fd = region->fd;
                }

                new_region->mapping_type = region->mapping_type;
                new_region->offset = offset + to_shave_off;
                new_region->mm = region->mm;
                new_region->flags = region->flags;

                if (!is_mapping_shared(region) && !vmo_is_shared(region->vmo))
                {
                    struct vm_object *second = vmo_split(offset, to_shave_off, region->vmo);
                    if (!second)
                    {
                        vm_remove_region(as, new_region);
                        /* TODO: Undo new_region stuff and free it */
                        return -ENOMEM;
                    }

                    if (as != &kernel_address_space)
                        add_vmo_to_private_list(as, second);

                    new_region->vmo = second;
                    vmo_assign_mapping(second, new_region);
                    /* We should need to do this */
                    new_region->offset = 0;
                }
                else
                {
                    vmo_assign_mapping(region->vmo, new_region);

                    vmo_ref(region->vmo);
                    new_region->vmo = region->vmo;
                }
            }
            else
            {
                region->pages -= to_shave_off >> PAGE_SHIFT;

                if (!is_mapping_shared(region) && !vmo_is_shared(region->vmo))
                    vmo_truncate(region->vmo, region->vmo->size - to_shave_off, 0);
            }
        }

        decrement_vm_stat(as, virtual_memory_size, to_shave_off);
        if (is_shared)
            decrement_vm_stat(as, shared_set_size, to_shave_off);
    }

    return 0;
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
    scoped_mutex g{as->vm_lock};

    auto addr = (unsigned long) __addr;
    if (addr < as->start || addr > as->end)
        return -EINVAL;
    if (size == 0)
        return -EINVAL;
    if (addr & (PAGE_SIZE - 1))
        return -EINVAL;

    vm_unmap_every_region_in_range(as, (unsigned long) __addr, size);
    return 0;
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

struct vm_region *vm_next_region(mm_address_space *as, vm_region *region)
{
    auto node = bst_next(&as->region_tree, &region->tree_node);

    return node ? container_of(node, vm_region, tree_node) : nullptr;
}

bool vm_can_expand(struct mm_address_space *as, struct vm_region *region, size_t new_size)
{
    /* Can always shrink the mapping */
    if (new_size < region->pages << PAGE_SHIFT)
        return true;

    auto next = vm_next_region(as, region);

    // If there's no region after this one, we're clear to expand
    // TODO: What if we overflow here?
    if (!next)
        return true;

    /* Calculate the hole size, and if >= new_size, we're good */
    size_t hole_size = next->base - region->base;

    return hole_size >= new_size;
}

int __vm_expand_mapping(struct vm_region *region, size_t new_size)
{
    size_t diff = new_size - (region->pages << PAGE_SHIFT);
    if (!vm_test_vs_rlimit(region->mm, new_size))
        return -ENOMEM;

    region->pages = new_size >> PAGE_SHIFT;
    vmo_resize(new_size, region->vmo);

    increment_vm_stat(region->mm, virtual_memory_size, diff);
    if (is_mapping_shared(region))
        increment_vm_stat(region->mm, shared_set_size, diff);

    return 0;
}

int vm_expand_mapping(struct mm_address_space *as, struct vm_region *region, size_t new_size)
{
    MUST_HOLD_MUTEX(&as->vm_lock);

    if (!vm_can_expand(as, region, new_size))
    {
        return -1;
    }

    return __vm_expand_mapping(region, new_size);
}

int vm_expand_brk(size_t nr_pages)
{
    struct process *p = get_current_process();
    struct vm_region *brk_region = vm_find_region(p->address_space->brk);
    assert(brk_region != nullptr);
    size_t new_size = (brk_region->pages + nr_pages) << PAGE_SHIFT;

    return vm_expand_mapping(get_current_address_space(), brk_region, new_size);
}

int mremap_check_for_overlap(void *__old_address, size_t old_size, void *__new_address,
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

void *vm_remap_create_new_mapping_of_shared_pages(void *new_address, size_t new_size, int flags,
                                                  void *old_address)
{
    struct process *current = get_current_process();
    void *ret = MAP_FAILED;
    bool fixed = flags & MREMAP_FIXED;
    struct vm_region *new_mapping = nullptr;

    struct vm_region *old_region = vm_find_region(old_address);
    if (!old_region)
    {
        ret = (void *) -EFAULT;
        goto out;
    }

    if (old_region->mapping_type != MAP_SHARED)
    {
        ret = (void *) -EINVAL;
        goto out;
    }

    if (fixed)
    {
        if (vm_sanitize_address(new_address, new_size >> PAGE_SHIFT) < 0)
        {
            ret = (void *) -EINVAL;
            goto out;
        }

        if (mremap_check_for_overlap(old_address, new_size, new_address, new_size) < 0)
        {
            ret = (void *) -EINVAL;
            goto out;
        }

        new_mapping = vm_create_region_at(new_address, new_size >> PAGE_SHIFT, VM_TYPE_REGULAR,
                                          old_region->rwx);
    }
    else
    {
        new_mapping = vm_allocate_region(
            current->get_aspace(), (unsigned long) current->address_space->mmap_base, new_size);
        if (new_mapping)
        {
            new_mapping->type = VM_TYPE_REGULAR;
            new_mapping->rwx = old_region->rwx;
        }
    }

    if (!new_mapping)
    {
        ret = (void *) -ENOMEM;
        goto out;
    }

    vm_copy_region(old_region, new_mapping);
    ret = (void *) new_mapping->base;
out:
    return ret;
}

void *vm_try_move(struct vm_region *old_region, unsigned long new_base, size_t new_size)
{
    struct process *current = get_current_process();

    vm_remove_region(current->get_aspace(), old_region);

    old_region->base = new_base;
    if (int st = __vm_expand_mapping(old_region, new_size); st < 0)
        return (void *) (unsigned long) st;

    /* TODO: What to do in case of a failure? */
    vm_add_region(current->get_aspace(), old_region);

    /* TODO: Maybe unmapping isn't the best option on a move and we should copy mappings */
    __vm_unmap_range((void *) old_region->base, old_region->pages);

    vm_print_umap();
    return (void *) old_region->base;
}

void *vm_remap_try(void *old_address, size_t old_size, void *new_address, size_t new_size,
                   int flags)
{
    size_t n;
    struct process *current = get_current_process();
    struct vm_region *reg = vm_find_region(old_address);
    if (!reg)
        return (void *) -EFAULT;

    struct vm_region *old_reg =
        vm_split_region(current->get_aspace(), reg, (unsigned long) old_address, old_size, &n);
    if (!old_reg)
        return (void *) -ENOMEM;

    if (vm_expand_mapping(current->get_aspace(), old_reg, new_size) < 0)
    {
        if (flags & MREMAP_MAYMOVE)
        {
            unsigned long new_base = vm_allocate_base(
                current->get_aspace(), (unsigned long) current->address_space->mmap_base, new_size);
            return vm_try_move(old_reg, new_base, new_size);
        }

        return (void *) -ENOMEM;
    }

    return (void *) old_reg->base;
}

bool limits_are_contained(struct vm_region *reg, unsigned long start, unsigned long limit)
{
    unsigned long reg_limit = reg->base + (reg->pages << PAGE_SHIFT);

    if (start <= reg->base && limit > reg->base)
        return true;
    if (reg->base <= start && reg_limit >= limit)
        return true;

    return false;
}

#define VM_UNMAP_EVERY_REGION_IN_RANGE_DEBUG 0

void vm_unmap_every_region_in_range(struct mm_address_space *as, unsigned long start,
                                    unsigned long length)
{
    __vm_munmap(as, (void *) start, length);
}

/* TODO: Test things */
void *sys_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address)
{
    // TODO: This is broken.
    return (void *) -ENOSYS;
    /* Check http://man7.org/linux/man-pages/man2/mremap.2.html for documentation */
    struct process *current = get_current_process();
    bool may_move = flags & MREMAP_MAYMOVE;
    bool fixed = flags & MREMAP_FIXED;
    bool wants_create_new_mapping_of_pages = old_size == 0 && may_move;
    void *ret = MAP_FAILED;
    scoped_mutex g{current->address_space->vm_lock};

    /* TODO: Unsure on what to do if new_size > old_size */

    if (vm_sanitize_address(old_address, old_size >> PAGE_SHIFT) < 0)
    {
        ret = (void *) -EFAULT;
        goto out;
    }

    if (wants_create_new_mapping_of_pages)
        return vm_remap_create_new_mapping_of_shared_pages(new_address, new_size, flags,
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
        ret = vm_remap_try(old_address, old_size, new_address, new_size, flags);
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

        struct vm_region *reg = vm_find_region(old_address);
        if (!reg)
        {
            ret = (void *) -EFAULT;
            goto out;
        }
        size_t n;

        struct vm_region *old_reg =
            vm_split_region(current->get_aspace(), reg, (unsigned long) old_address, old_size, &n);
        if (!old_reg)
        {
            ret = (void *) -ENOMEM;
            goto out;
        }

        vm_unmap_every_region_in_range(current->get_aspace(), (unsigned long) new_address,
                                       new_size);

        ret = vm_try_move(old_reg, (unsigned long) new_address, new_size);
    }

out:
    return ret;
}

/**
 * @brief Commits a virtual page.
 *
 * @param page Pointer to the virtual address to be committed.
 * @return A pointer to the backing struct page.
 */
struct page *vm_commit_page(void *page)
{
    struct vm_region *reg = vm_find_region(page);
    if (!reg)
        return nullptr;

    if (!reg->vmo)
        return nullptr;

    struct vm_object *vmo = reg->vmo;

    unsigned long off = reg->offset + ((unsigned long) page - reg->base);
    struct page *p;

    vmo_status_t st = vmo_get(vmo, off, VMO_GET_MAY_POPULATE, &p);
    if (st != VMO_STATUS_OK)
        return nullptr;

    if (!map_pages_to_vaddr(page, page_to_phys(p), PAGE_SIZE, reg->rwx))
    {
        page_unpin(p);
        return nullptr;
    }

    page_unpin(p);

    return p;
}

int vm_change_locks_range_in_region(struct vm_region *region, unsigned long addr, unsigned long len,
                                    unsigned long flags)
{
    assert(region->vmo != nullptr);

    scoped_mutex g{region->vmo->page_lock};

    struct rb_itor it;
    it.node = nullptr;
    it.tree = region->vmo->pages;
    unsigned long starting_off = region->offset + (addr - region->base);
    unsigned long end_off = starting_off + len;
    bool node_valid = rb_itor_search_ge(&it, (void *) starting_off);

    while (node_valid)
    {
        struct page *p = (page *) *rb_itor_datum(&it);
        size_t poff = (size_t) rb_itor_key(&it);

        if (poff >= end_off)
            return 0;
        if (flags & VM_LOCK)
            p->flags |= PAGE_FLAG_LOCKED;
        else
            p->flags &= ~(PAGE_FLAG_LOCKED);

        node_valid = rb_itor_next(&it);
    }

    return 0;
}

int vm_change_region_locks(void *__start, unsigned long length, unsigned long flags)
{
    /* We don't need to do this with kernel addresses */

    if (is_higher_half(__start))
        return 0;

    struct mm_address_space *as = get_current_process()->get_aspace();

    unsigned long limit = (unsigned long) __start + length;
    unsigned long addr = (unsigned long) __start;

    scoped_mutex g{as->vm_lock};

    while (addr < limit)
    {
        struct vm_region *region = vm_find_region((void *) addr);
        if (!region)
            return -EINVAL;

        size_t len = min(length, region->pages << PAGE_SHIFT);
        if (vm_change_locks_range_in_region(region, addr, len, flags) < 0)
            return -ENOMEM;

        if (flags & VM_FUTURE_PAGES)
        {
            if (flags & VM_LOCK)
                region->vmo->flags |= VMO_FLAG_LOCK_FUTURE_PAGES;
            else
                region->vmo->flags &= ~VMO_FLAG_LOCK_FUTURE_PAGES;
        }

        addr += len;
        length -= len;
    }

    return 0;
}

void vm_wp_page(struct mm_address_space *mm, void *vaddr)
{
    assert(paging_write_protect(vaddr, mm) == true);

    mmu_invalidate_range((unsigned long) vaddr, 1, mm);
}

/**
 * @brief Write-protects a page in each of its mappings.
 *
 * @param page The page that needs to be write-protected.
 * @param offset The offset of the page in the VMO.
 * @param vmo A pointer to its VMO.
 */
void vm_wp_page_for_every_region(page *page, size_t page_off, vm_object *vmo)
{
    vmo->for_every_mapping([page_off](vm_region *region) -> bool {
        scoped_mutex g{region->mm->vm_lock};
        const size_t mapping_off = (size_t) region->offset;
        const size_t mapping_size = region->pages << PAGE_SHIFT;

        if (page_off >= mapping_off && mapping_off + mapping_size > page_off)
        {
            /* The page is included in this mapping, so WP it */
            const unsigned long vaddr = region->base + (page_off - mapping_off);
            vm_wp_page(region->mm, (void *) vaddr);
        }

        return true;
    });
}

int get_phys_pages_direct(unsigned long addr, unsigned int flags, struct page **pages,
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

int gpp_try_to_fault_in(unsigned long addr, struct vm_region *entry, unsigned int flags)
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

int __get_phys_pages(struct vm_region *region, unsigned long addr, unsigned int flags,
                     struct page **pages, size_t nr_pgs)
{
    unsigned long page_rwx_mask = (flags & GPP_READ ? PAGE_PRESENT : 0) |
                                  (flags & GPP_WRITE ? PAGE_WRITABLE : 0) |
                                  (flags & GPP_USER ? PAGE_USER : 0);

    for (size_t i = 0; i < nr_pgs; i++, addr += PAGE_SIZE)
    {
    retry:;
        unsigned long mapping_info = get_mapping_info((void *) addr);

        if ((mapping_info & page_rwx_mask) != page_rwx_mask)
        {
            int st = gpp_try_to_fault_in(addr, region, flags);

            if (!(st & GPP_ACCESS_OK))
                return st;
            goto retry;
        }

        unsigned long paddr = MAPPING_INFO_PADDR(mapping_info);

        struct page *page = phys_to_page(paddr);

        pages[i] = page;
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
    bool is_user = flags & GPP_USER;
    int ret = GPP_ACCESS_OK;
    bool had_shared_pages = false;
    size_t number_of_pages = nr_pgs;

    struct mm_address_space *as = is_user ? get_current_address_space() : &kernel_address_space;

    unsigned long addr = (unsigned long) _addr;

    if (addr >= PHYS_BASE && (addr + (nr_pgs << PAGE_SHIFT)) < PHYS_BASE_LIMIT)
    {
        ret = get_phys_pages_direct(addr, flags, pages, nr_pgs);
        return ret;
    }

    scoped_mutex g{as->vm_lock};

    size_t pages_gotten = 0;

    while (nr_pgs)
    {
        struct vm_region *reg = vm_find_region((void *) addr);

        if (!reg)
        {
            ret = GPP_ACCESS_FAULT;
            goto out;
        }

        if (reg->mapping_type == MAP_SHARED)
            had_shared_pages = true;

        /* Do a permission check. */
        unsigned int rwx_mask = (flags & GPP_READ ? VM_READ : 0) |
                                (flags & GPP_WRITE ? VM_WRITE : 0) |
                                (flags & GPP_USER ? VM_USER : 0);

        if ((reg->rwx & rwx_mask) != rwx_mask)
        {
            ret = GPP_ACCESS_FAULT;
            goto out;
        }

        /* Calculate the number of pages we can resolve in this region */
        size_t vm_region_off_pgs = (reg->base - addr) >> PAGE_SHIFT;
        size_t max_resolved_pgs = reg->pages - vm_region_off_pgs;
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

    /* Now that we're done, we're pinning the pages we just got */

    for (size_t i = 0; i < number_of_pages; i++)
        page_pin(pages[i]);

out:
    if (ret & GPP_ACCESS_OK && had_shared_pages)
        ret |= GPP_ACCESS_SHARED;

    return ret;
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
    if (flags & MS_ASYNC || !flags)
        return 0; // NOOP

    return -ENOSYS;
}

/**
 * @brief Creates a new standalone address space
 *
 * @return Ref guard to a mm_address_space, or a negative status code
 */
expected<ref_guard<mm_address_space>, int> mm_address_space::create()
{
    ref_guard<mm_address_space> as = make_refc<mm_address_space>();
    if (!as)
        return unexpected<int>{-ENOENT};

    spinlock_init(&as->page_table_lock);
    bst_root_initialize(&as->region_tree);

    int st = vm_clone_as(as.get());
    if (st < 0)
        return unexpected<int>{st};
    return as;
}

/**
 * @brief Creates a new standalone address space by forking
 *
 * @return Ref guard to a mm_address_space, or a negative status code
 */
expected<ref_guard<mm_address_space>, int> mm_address_space::fork()
{
    ref_guard<mm_address_space> as = make_refc<mm_address_space>();
    if (!as)
        return unexpected<int>{-ENOENT};

    spinlock_init(&as->page_table_lock);
    bst_root_initialize(&as->region_tree);

    int st = vm_fork_address_space(as.get());
    if (st < 0)
        return unexpected<int>{st};
    return as;
}

/**
 * @brief Loads an address space
 *
 * @param aspace Address space to load
 * @param cpu CPU we're on
 */
void vm_load_aspace(mm_address_space *aspace, unsigned int cpu)
{
    vm_load_arch_mmu(&aspace->arch_mmu);
    if (cpu == -1U) [[unlikely]]
        cpu = get_cpu_nr();
    aspace->active_mask.set_cpu_atomic(cpu);
}

/**
 * @brief Sets the current address space, and returns the old one
 *
 * @param aspace Address space to set and load
 * @return The old address space
 */
mm_address_space *vm_set_aspace(mm_address_space *aspace)
{
    mm_address_space *ret = &kernel_address_space;
    auto thread = get_current_thread();
    if (thread)
    {
        ret = thread->get_aspace();
        thread->set_aspace(aspace);
    }

    vm_load_aspace(aspace);

    return ret;
}

/**
 * @brief Destroys the mm_address_space object
 *
 */
mm_address_space::~mm_address_space()
{
    vm_destroy_addr_space(this);
}
