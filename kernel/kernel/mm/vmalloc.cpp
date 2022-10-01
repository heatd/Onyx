/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <lib/binary_search_tree.h>

#include <onyx/spinlock.h>
#include <onyx/vm.h>

#include <onyx/mm/pool.hpp>
#include <onyx/utility.hpp>

struct vmalloc_tree
{
    struct bst_root root;
    struct spinlock lock;
    unsigned long start;
    unsigned long length;
} vmalloc_tree;

struct vmalloc_region
{
    unsigned long addr;
    size_t pages;
    struct bst_node tree_node;
    int perms;
    page *backing_pgs;
};

/* Adapted from vm.cpp */

/**
 * @brief Allocates a base for a new vmalloc region
 * Note that this function does not check if the base + size >= end of vmalloc.
 *
 * @param as Address space
 * @param min Minimum address
 * @param size Size of the region
 * @return New base
 */
static unsigned long vmalloc_allocate_base(struct vmalloc_tree *as, unsigned long min, size_t size)
{
    MUST_HOLD_LOCK(&as->lock);

    min = cul::max(min, as->start);

    struct a : bst_node
    {
        unsigned long min;
    } priv;

    priv.min = min;

    auto compare = [](bst_node *node0, bst_node *fake) -> int {
        struct a *priv = (a *) fake;
        auto reg = container_of(node0, vmalloc_region, tree_node);
        auto end = reg->addr + (reg->pages << PAGE_SHIFT) - 1;
        if (check_for_overlap(reg->addr, end, priv->min, priv->min + PAGE_SIZE))
            return 0;
        else if (end >= priv->min)
            return -1;
        else // if (end < priv->min)
            return 1;
    };

    struct bst_node *node = nullptr;
    unsigned long last_end = min;
    struct vmalloc_region *f = nullptr;

    if (min != as->start)
    {
        node = bst_search(&as->root, &priv, compare);
    }
    else
    {
        node = bst_min(&as->root, nullptr);
    }

    if (!node)
        goto done;

    /* Check if there's a gap between the first node
     * and the start of the address space
     */

    f = container_of(node, vmalloc_region, tree_node);

#if DEBUG_VM_1
    printk("Tiniest node: %016lx\n", f->addr);
#endif
    if (f->addr - min >= size)
    {
#if DEBUG_VM_2
        printk("gap [%016lx - %016lx]\n", min, f->addr);
#endif
        goto done;
    }

    while (node)
    {
        f = container_of(node, vmalloc_region, tree_node);
        last_end = f->addr + (f->pages << PAGE_SHIFT);

        node = bst_next(&as->root, node);
        if (!node)
            break;

        struct vmalloc_region *vm = container_of(node, vmalloc_region, tree_node);

        if (vm->addr - last_end >= size && min <= vm->addr)
            break;
    }

done:
    last_end = last_end < min ? min : last_end;

    return last_end;
}

static memory_pool<vmalloc_region> pool;

/**
 * @brief Create and insert a new vmalloc region to the tree
 *
 * @param tree Tree
 * @param start Start of the region
 * @param pages Number of pages of the region
 * @param perms Permissions
 * @return Pointer to a vmalloc_region, or nullptr
 */
struct vmalloc_region *vmalloc_insert_region(struct vmalloc_tree *tree, unsigned long start,
                                             size_t pages, int perms)
{
    auto reg = pool.allocate();
    if (!reg)
        return nullptr;
    reg->addr = start;
    reg->pages = pages;
    reg->perms = perms;
    bst_node_initialize(&reg->tree_node);
    auto success = bst_insert(
        &tree->root, &reg->tree_node, [](struct bst_node *lhs_, struct bst_node *rhs_) -> int {
            auto lhs = container_of(lhs_, vmalloc_region, tree_node);
            auto rhs = container_of(rhs_, vmalloc_region, tree_node);

            if (check_for_overlap(lhs->addr, lhs->addr + (lhs->pages << PAGE_SHIFT) - 1, rhs->addr,
                                  rhs->addr + (rhs->pages << PAGE_SHIFT) - 1))
            {
                panic("vmalloc: Region [%lx, %lx] and [%lx, %lx] overlap\n", lhs->addr,
                      lhs->addr + (lhs->pages << PAGE_SHIFT), rhs->addr,
                      rhs->addr + (rhs->pages << PAGE_SHIFT));
                return 0;
            }
            else if (rhs->addr > lhs->addr)
                return 1;
            else
                return -1;
        });
    assert(success == true);
    return reg;
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
void *vmalloc(size_t pages, int type, int perms)
{
    scoped_lock g{vmalloc_tree.lock};
    auto start = vmalloc_allocate_base(&vmalloc_tree, 0, pages << PAGE_SHIFT);

    if (start + (pages << PAGE_SHIFT) > vmalloc_tree.start + vmalloc_tree.length)
        return errno = ENOMEM, nullptr;

    auto vmal_reg = vmalloc_insert_region(&vmalloc_tree, start, pages, perms);
    if (!vmal_reg)
        return errno = ENOMEM, nullptr;

    auto delvmr = [vmal_reg]() {
        bst_delete(&vmalloc_tree.root, &vmal_reg->tree_node);
        pool.free(vmal_reg);
    };

    auto pgs = alloc_pages(pages, 0);
    if (!pgs)
    {
        delvmr();
        return errno = ENOMEM, nullptr;
    }

    page *it = pgs;
    for (size_t i = 0; i < pages; i++, it = it->next_un.next_allocation)
    {
        bool success = vm_map_page(&kernel_address_space, vmal_reg->addr + (i << PAGE_SHIFT),
                                   (uint64_t) page_to_phys(it), vmal_reg->perms) != nullptr;
        if (!success)
        {
            free_pages(pgs);
            vm_mmu_unmap(&kernel_address_space, (void *) vmal_reg->addr, i);
            delvmr();
            return errno = ENOMEM, nullptr;
        }
    }

    vmal_reg->backing_pgs = pgs;

    return (void *) vmal_reg->addr;
}

/**
 * @brief Find a vmalloc region in the tree
 *
 * @param ptr Pointer to memory
 * @return Corresponding vmalloc_region, or nullptr
 */
static struct vmalloc_region *vfind(void *ptr)
{
    struct vmalloc_region fake;
    fake.addr = (unsigned long) ptr;
    fake.pages = 1;
    bst_node_initialize(&fake.tree_node);

    auto node =
        bst_search(&vmalloc_tree.root, &fake.tree_node,
                   [](struct bst_node *lhs_, struct bst_node *rhs_) -> int {
                       auto lhs = container_of(lhs_, vmalloc_region, tree_node);
                       auto rhs = container_of(rhs_, vmalloc_region, tree_node);

                       if (check_for_overlap(lhs->addr, lhs->addr + (lhs->pages << PAGE_SHIFT) - 1,
                                             rhs->addr, rhs->addr + (rhs->pages << PAGE_SHIFT) - 1))
                           return 0;
                       else if (rhs->addr > lhs->addr)
                           return 1;
                       else
                           return -1;
                   });
    return !node ? nullptr : container_of(node, vmalloc_region, tree_node);
}

/**
 * @brief Frees a region of memory previously allocated by vmalloc.
 *
 * @param ptr A pointer to the allocation.
 * @param pages The number of pages it consists in.
 */
void vfree(void *ptr, size_t pages)
{
    scoped_lock g{vmalloc_tree.lock};
    if ((unsigned long) ptr & (PAGE_SIZE - 1))
        panic("vfree: Pointer %p not page aligned\n", ptr);

    // We do a bunch of sanity checks
    auto reg = vfind(ptr);
    if (!reg)
    {
        panic("vfree: Bad pointer %p not mapped\n", ptr);
    }

    if (reg->addr != (unsigned long) ptr)
    {
        panic("vfree: Pointer %p does not point to start of vmalloc allocation %lx\n", ptr,
              reg->addr);
    }

    if (reg->pages != pages)
    {
        panic("vfree: Given length %lx does not match with vmalloc allocation length %lx\n",
              pages << PAGE_SHIFT, reg->pages << PAGE_SHIFT);
    }

    // First, free the pages, then unmap the memory, then finally unlink it
    free_pages(reg->backing_pgs);

    vm_mmu_unmap(&kernel_address_space, (void *) reg->addr, reg->pages);

    // Remove the node from the tree
    bst_delete(&vmalloc_tree.root, &reg->tree_node);

    // and delete it
    pool.free(reg);
}

/**
 * @brief Initialize the vmalloc allocator
 *
 * @param start Start of the vmalloc region
 * @param length Length of the vmalloc region
 */
void vmalloc_init(unsigned long start, unsigned long length)
{
    bst_root_initialize(&vmalloc_tree.root);
    vmalloc_tree.start = start;
    vmalloc_tree.length = length;
    spinlock_init(&vmalloc_tree.lock);
}
