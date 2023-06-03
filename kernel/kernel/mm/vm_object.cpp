/*
 * Copyright (c) 2018 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <stdio.h>
#include <sys/mman.h>

#include <onyx/file.h>
#include <onyx/ioctx.h>
#include <onyx/mm/vm_object.h>
#include <onyx/page.h>
#include <onyx/panic.h>
#include <onyx/scoped_lock.h>
#include <onyx/utils.h>
#include <onyx/vm.h>

#include <onyx/utility.hpp>

vm_object::vm_object()
{
    INIT_LIST_HEAD(&mappings);
    mutex_init(&page_lock);
    mutex_init(&mapping_lock);
}

/**
 * @brief Creates a new VMO.
 *
 * @param size The size of the VMO.
 * @param priv Pointer to private, optional.
 * @return A pointer to the new VMO, or NULL if out of memory.
 */
vm_object *vmo_create(size_t size, void *priv)
{
    vm_object *vmo = new vm_object;
    if (!vmo)
        return nullptr;

    /* Default to backed */
    vmo->size = cul::align_up2(size, PAGE_SIZE);
    vmo->priv = priv;

    return vmo;
}

/*
 * Commits a page for a VMO backed by physical memory
 */
vmo_status_t vmo_commit_phys_page(vm_object *vmo, size_t off, page **ppage)
{
    struct page *p = alloc_page(0);
    if (!p)
        return VMO_STATUS_OUT_OF_MEM;

    *ppage = p;
    return VMO_STATUS_OK;
}

const struct vm_object_ops vmo_phys_ops = {.commit = vmo_commit_phys_page};

/**
 * @brief Creates a new anonymously backed VMO.
 *
 * @param size The size of the VMO.
 *
 * @return A pointer to the new VMO, or NULL if out of memory.
 */
vm_object *vmo_create_phys(size_t size)
{
    vm_object *vmo = vmo_create(size, nullptr);
    if (!vmo)
        return nullptr;

    vmo->ops = &vmo_phys_ops;
    vmo->type = VMO_ANON;

    return vmo;
}

/**
 * @brief Insert a page into the vmo
 *
 * @param off Offset into the vmo, in bytes
 * @param page struct page to insert
 * @return 0 on success, negative error codes (ENOMEM)
 */
int vm_object::insert_page_unlocked(unsigned long off, struct page *page)
{
    if (int st0 = vm_pages.store(off >> PAGE_SHIFT, (unsigned long) page); st0 < 0)
    {
        return st0;
    }

    return 0;
}

/*
 * Populates a VMO
 */
#include <onyx/timer.h>

vmo_status_t vmo_populate(vm_object *vmo, size_t off, page **ppage)
{
    MUST_HOLD_MUTEX(&vmo->page_lock);
    assert(vmo->ops != nullptr && vmo->ops->commit != nullptr);

    // hrtime_t s = get_main_clock()->get_ns();
    struct page *page;

    vmo_status_t st = vmo->ops->commit(vmo, off, &page);

    if (st != VMO_STATUS_OK)
    {
        return st;
    }
    else
    {
        assert(page != nullptr);
    }

    // hrtime_t end = get_main_clock()->get_ns();

    if (int st0 = vmo->insert_page_unlocked(off, page); st0 < 0)
    {
        free_page(page);
        return VMO_STATUS_OUT_OF_MEM;
    }

    if (vmo->flags & VMO_FLAG_LOCK_FUTURE_PAGES)
        page->flags |= PAGE_FLAG_LOCKED;

    *ppage = page;

    return VMO_STATUS_OK;
}

/**
 * @brief Fetch a page from a VM object
 *
 * @param vmo
 * @param off The offset inside the vm object
 * @param flags The valid flags are defined above (may populate, may not implicit cow)
 * @param ppage Pointer to where the struct page will be placed
 * @return The vm_status_t of the request
 */
vmo_status_t vmo_get(vm_object *vmo, size_t off, unsigned int flags, struct page **ppage)
{
    vmo_status_t st = VMO_STATUS_OK;

    bool may_populate = flags & VMO_GET_MAY_POPULATE;
    bool may_not_implicit_cow = flags & VMO_GET_MAY_NOT_IMPLICIT_COW;
    bool is_cow = vmo->cow_clone != nullptr;

    struct page *p = nullptr;

#if 0
    if (vmo->ino && !(vmo->flags & VMO_FLAG_DEVICE_MAPPING))
        vmo->size = vmo->ino->i_size;
#endif

    if (off >= vmo->size)
    {
        return VMO_STATUS_BUS_ERROR;
    }

    scoped_mutex g{vmo->page_lock};

    auto ex = vmo->vm_pages.get(off >> PAGE_SHIFT);
    if (ex.has_value())
    {
        p = (struct page *) ex.value();
    }

    if (!p && is_cow && !may_not_implicit_cow)
    {
        struct page *new_page = alloc_page(PAGE_ALLOC_NO_ZERO);
        if (!new_page)
        {
            return VMO_STATUS_OUT_OF_MEM;
        }

        size_t vmo_off = (off_t) vmo->priv;
        struct page *old_page;

        // printk("clone size: %lx\n", vmo->cow_clone->ino->i_size);
        auto st = vmo_get(vmo->cow_clone, off + vmo_off, flags & ~VMO_GET_MAY_NOT_IMPLICIT_COW,
                          &old_page);
        if (st != VMO_STATUS_OK)
        {
            // printk("failed\n");
            free_page(new_page);
            return st;
        }

        copy_page_to_page(page_to_phys(new_page), page_to_phys(old_page));

        page_unpin(old_page);

        int err = vmo->insert_page_unlocked(off, new_page);
        if (err < 0)
        {
            free_page(new_page);
            return VMO_STATUS_OUT_OF_MEM;
        }

        p = new_page;
    }

    if (!p && may_populate)
    {
        st = vmo_populate(vmo, off, &p);
    }
    else if (!p)
    {
        st = VMO_STATUS_NON_EXISTENT;
    }

    if (st == VMO_STATUS_OK)
    {
        page_pin(p);
        *ppage = p;
    }

    return st;
}

void vmo_rb_delete_func(void *key, void *data)
{
    struct page *p = (page *) data;

    // TODO: Memory leak here! We might be a special kind of VMO that needs to free other
    // structures. A good example of an object like this is inode vmos.
    free_page(p);
}

/**
 * @brief Forks the VMO, performing any COW tricks that may be required.
 *
 * @param vmo The VMO to be forked.
 * @param shared True if the region is shared. This makes it skip all the work.
 * @param reg The new forked region.
 * @return The vm object to be refed and used by the new region.
 */
vm_object *vmo_fork(vm_object *vmo, bool shared, struct vm_region *reg)
{
    vm_object *new_vmo;

    if (shared)
    {
        /* Shared mappings have the peculiarity of just being a atomic add to the refc,
         * and an append to a mappings list. Therefore, we don't need to do anything here,
         * since it will be handled by each vm region's forking(fork_vm_region, mm/vm.c).
         */

        return vmo;
    }

    /* Private mappings require a new copy of the vmo to be created, so we can fork it
     * correctly. */

    new_vmo = vmo_create(vmo->size, vmo->priv);
    if (!new_vmo)
        return nullptr;

    new_vmo->flags = vmo->flags;
    /* Locks are not inherited */
    new_vmo->flags &= ~(VMO_FLAG_LOCK_FUTURE_PAGES);
    new_vmo->prev_private = new_vmo->next_private = nullptr;
    new_vmo->forked_from = vmo;
    new_vmo->ino = vmo->ino;
    new_vmo->ops = vmo->ops;
    new_vmo->type = vmo->type;
    new_vmo->priv = vmo->priv;

    scoped_mutex g{vmo->page_lock};

    auto ex = vmo->vm_pages.copy(
        [](unsigned long entry, void * /*ctx*/) -> unsigned long {
            struct page *p = (struct page *) entry;
            page_ref(p);
            return entry;
        },
        nullptr);

    if (ex.has_error())
    {
        delete new_vmo;
        return nullptr;
    }

    new_vmo->vm_pages = ex.value();

    g.unlock();

    new_vmo->cow_clone = vmo->cow_clone;

    if (new_vmo->cow_clone)
        vmo_ref(new_vmo->cow_clone);

    return new_vmo;
}

/**
 * @brief Prefaults a region of a vm object with anonymous pages.
 * This is only used by kernel vm objects, that are forced to not have any non-anon
 * backing.
 *
 * @param vmo The VMO to be prefaulted.
 * @param size The size of the prefault.
 * @param offset The offset of the region to be prefaulted.
 * @return 0 on success, -1 on error.
 */
int vmo_prefault(vm_object *vmo, size_t size, size_t offset)
{
    size_t pages = vm_size_to_pages(size);

    struct page *p = alloc_pages(pages, 0);
    if (!p)
    {
        printk("alloc_pages failed: could not allocate %lu pages!\n", pages);
        return -1;
    }

    struct page *_p = p;
    for (size_t i = 0; i < pages; i++, offset += PAGE_SIZE)
    {
        int err = vmo->insert_page_unlocked(offset, _p);
        if (err < 0)
        {
            free_pages(p);
            return err;
        }

        _p = _p->next_un.next_allocation;
    }

    return 0;
}

/**
 * @brief Destroys the VMO, disregarding any refcount.
 * This should not be called arbitrarily and only in cases where it's certain
 * that we hold the only reference.
 *
 * @param vmo The VMO to be destroyed.
 */
void vmo_destroy(vm_object *vmo)
{
    // No need to hold the lock considering we're the last reference.
    if (vmo->cow_clone)
        vmo_unref(vmo->cow_clone);

    delete vmo;
}

/**
 * @brief Maps a page into the VMO.
 *
 * @param off Offset of the page inside the VMO.
 * @param p Page to be mapped on the vmo.
 * @param vmo The VMO.
 * @return 0 on success, -1 on failure to map.
 */
int vmo_add_page(size_t off, struct page *p, vm_object *vmo)
{
    scoped_mutex g{vmo->page_lock};
    return vmo->insert_page_unlocked(off, p);
}

/**
 * @brief Releases the vmo, and destroys it if it was the last reference.
 *
 * @param vmo The VMO to be unrefed.
 * @return True if it was destroyed, false if it's still alive.
 */
bool vmo_unref(vm_object *vmo)
{
    if (__sync_sub_and_fetch(&vmo->refcount, 1) == 0)
    {
        // printk("Deleting vmo %p with size %lx\n", vmo, vmo->size);
        vmo_destroy(vmo);
        return true;
    }
    else
    {
        // printk("Unrefed vmo %p with size %lx\n", vmo, vmo->size);
        // printk("Vmo ino: %p Refs: %lu\n", vmo->ino, vmo->refcount);
    }

    return false;
}

static inline bool is_included(size_t lower, size_t upper, size_t x)
{
    return x >= lower && x < upper;
}

static inline bool is_excluded(size_t lower, size_t upper, size_t x)
{
    return x < lower || x > upper;
}

#define PURGE_SHOULD_FREE (1 << 0)
#define PURGE_EXCLUDE     (1 << 1)
#define PURGE_DO_NOT_LOCK (1 << 2)

int vmo_purge_pages(size_t lower_bound, size_t upper_bound, unsigned int flags, vm_object *second,
                    vm_object *vmo)
{
    scoped_mutex g{vmo->page_lock, !(flags & PURGE_DO_NOT_LOCK)};

    bool should_free = flags & PURGE_SHOULD_FREE;
    bool exclusive = flags & PURGE_EXCLUDE;

    assert(!(should_free && second != nullptr));

    bool (*compare_function)(size_t, size_t, size_t) = is_included;

    if (exclusive)
        compare_function = is_excluded;

    auto cursor = radix_tree::cursor::from_index(&vmo->vm_pages);

    while (!cursor.is_end())
    {
        struct page *p = (page *) cursor.get();
        size_t off = cursor.current_idx() << PAGE_SHIFT;

        if (compare_function(lower_bound, upper_bound, off))
        {
            cursor.store(0);

            struct page *old_p = p;

            if (should_free)
            {
                vmo->unmap_page(off);
                if (!vmo->ops->free_page)
                    free_page(old_p);
                else
                    vmo->ops->free_page(vmo, old_p);
            }

            if (second)
                vmo_add_page(off, old_p, second);
        }

        cursor.advance();
    }

    return 0;
}

/**
 * @brief Unmaps a single page from every mapping
 *
 * @param offset Offset of the page
 */
void vm_object::unmap_page(size_t offset)
{
    for_every_mapping([offset](vm_region *reg) -> bool {
        auto off = (off_t) offset;
        const off_t vmregion_end = reg->offset + (reg->pages << PAGE_SHIFT);
        if (reg->offset <= off && vmregion_end > off)
        {
            // Unmap it
            vm_mmu_unmap(reg->mm, (void *) (reg->base + offset - reg->offset), 1);
        }

        return true;
    });
}

int vmo_resize(size_t new_size, vm_object *vmo)
{
    bool needs_to_purge = new_size < vmo->size;
    vmo->size = new_size;
    if (needs_to_purge)
        vmo_purge_pages(0, new_size, PURGE_SHOULD_FREE | PURGE_EXCLUDE, nullptr, vmo);

    return 0;
}

vm_object *vmo_create_copy(vm_object *vmo)
{
    vm_object *copy = vmo_create(vmo->size, vmo->priv);

    if (!copy)
        return nullptr;

    copy->flags = vmo->flags;
    copy->cow_clone = vmo->cow_clone;
    copy->ino = vmo->ino;
    if (copy->ino)
        inode_ref(copy->ino);
    copy->ops = vmo->ops;
    copy->type = vmo->type;

    copy->flags &= ~(VMO_FLAG_LOCK_FUTURE_PAGES);
    if (copy->cow_clone)
        vmo_ref(copy->cow_clone);

    return copy;
}

/**
 * @brief Creates a new vmo and moves all pages in [split_point, split_point + hole_size] to it.
 *
 * @param split_point The start of the split point.
 * @param hole_size The size of the hole.
 * @param vmo The VMO to be split.
 * @return The new vmo populated with all pre-existing vmo pages in the range.
 */
vm_object *vmo_split(size_t split_point, size_t hole_size, vm_object *vmo)
{
    vm_object *second_vmo = vmo_create_copy(vmo);

    if (!second_vmo)
        return nullptr;

    second_vmo->size -= split_point + hole_size;
    INIT_LIST_HEAD(&second_vmo->mappings);

    unsigned long max = hole_size + split_point;

    if (vmo_purge_pages(split_point, max, PURGE_SHOULD_FREE, nullptr, vmo) < 0 ||
        vmo_purge_pages(max, vmo->size, 0, second_vmo, vmo) < 0)
    {
        vmo_destroy(second_vmo);
        return nullptr;
    }

    vmo->size -= hole_size + second_vmo->size;

    return second_vmo;
}

/**
 * @brief Does a brief sanity check on the VMO.
 * This is only present for debugging purposes and should not be called.
 *
 * @param vmo The VMO.
 */
void vmo_sanity_check(vm_object *vmo)
{
    scoped_mutex g{vmo->page_lock};

#if 0
    struct rb_itor *it = rb_itor_new(vmo->pages);
    assert(it != nullptr);
    bool node_valid = rb_itor_next(it);
    while (node_valid)
    {
        struct page *p = (page *) *rb_itor_datum(it);
        size_t poff = (size_t) rb_itor_key(it);
        if (poff > vmo->size)
        {
            printk("Bad vmobject: p->off > nr_pages << PAGE_SHIFT.\n");
            printk("struct page: %p\n", p);
            printk("Offset: %lx\n", poff);
            printk("Size: %lx\n", vmo->size);
            panic("bad vmobject");
        }

        if (p->ref == 0)
        {
            printk("Bad vmobject:: p->ref == 0.\n");
            printk("struct page: %p\n", p);
            panic("bad vmobject");
        }
    }
#endif
}

/**
 * @brief Increments the reference counter on the VMO.
 *
 * @param vmo The VMO.
 */
void vmo_ref(vm_object *vmo)
{
    __sync_add_and_fetch(&vmo->refcount, 1);
}

/**
 * @brief Registers a new mapping on the VMO.
 *
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_assign_mapping(vm_object *vmo, vm_region *region)
{
    scoped_mutex g{vmo->mapping_lock};

    list_add_tail(&region->vmo_head, &vmo->mappings);
}

/**
 * @brief Removes a mapping on the VMO.
 *
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_remove_mapping(vm_object *vmo, vm_region *region)
{
    scoped_mutex g{vmo->mapping_lock};

    list_remove(&region->vmo_head);
}

/**
 * @brief Determines whether or not the VMO is currently being shared.
 *
 * @param vmo The VMO.
 * @return True if it is, false if not.
 */
bool vmo_is_shared(vm_object *vmo)
{
    return vmo->refcount != 1;
}

/**
 * @brief Does copy-on-write for MAP_PRIVATE mappings.
 *
 * @param vmo The new VMO.
 * @param target The copy-on-write master.
 */
void vmo_do_cow(vm_object *vmo, vm_object *target)
{
    assert(vmo->cow_clone == nullptr);
    assert(target != nullptr);
    vmo_ref(target);
    vmo->cow_clone = target;
}

/**
 * @brief Gets a page from the copy-on-write master.
 *
 * @param vmo The VMO.
 * @param off Offset of the page.
 * @param ppage Pointer to a page * where the result will be placed.
 * @return Status of the vmo get().
 */
vmo_status_t vmo_get_cow_page(vm_object *vmo, size_t off, struct page **ppage)
{
    size_t vmo_off = (off_t) vmo->priv;
    struct page *p;

    auto st = vmo_get(vmo->cow_clone, vmo_off + off, VMO_GET_MAY_POPULATE, &p);

    if (st != VMO_STATUS_OK)
        return st;

    /* Don't forget to ref the page! */
    page_ref(p);

    /* TODO: Race condition here? */

    if (vmo_add_page(off, p, vmo) < 0)
        page_unpin(p);

    *ppage = p;
    return st;
}

/**
 * @brief Un-COW's a VMO.
 *
 * @param vmo The VMO to be uncowed.
 */
void vmo_uncow(vm_object *vmo)
{
    // FIXME: This is weird. It never gets called.
    vmo_unref(vmo->cow_clone);
    vmo->cow_clone = nullptr;
}

/**
 * @brief Does copy-on-write of a page that is present and just got written to.
 *
 * @param vmo The VMO.
 * @param off Offset of the page.
 * @return The struct page of the new copied-to page.
 */
struct page *vmo_cow_on_page(vm_object *vmo, size_t off)
{
    scoped_mutex g{vmo->page_lock};

    auto ex = vmo->vm_pages.get(off >> PAGE_SHIFT);
    auto old_page = (struct page *) ex.unwrap();

    if (old_page == nullptr)
        panic("Fatal COW bug - page not found in VMO");

    if (old_page->ref == 1)
    {
        page_ref(old_page);
        // Great, we're the only ref, bail out and return this page
        return old_page;
    }

    struct page *new_page = alloc_page(PAGE_ALLOC_NO_ZERO);
    if (!new_page)
        return nullptr;

    copy_page_to_page(page_to_phys(new_page), page_to_phys(old_page));

    // printf("COW'd page %p to vmo %p (refs %lu)\n", page_to_phys(new_page), vmo, vmo->refcount);

    int st = vmo->vm_pages.store(off >> PAGE_SHIFT, (unsigned long) new_page);

    DCHECK(st == 0);

    page_pin(new_page);

    page_unref(old_page);

    return new_page;
}

/**
 * @brief Punches a hole into the given vmo, using the optional parameter `func` as a free page
 * callback.
 *
 * @param vmo The VMO
 * @param start The start of the hole
 * @param length The length of the hole
 * @param func The function callback for freeing pages, IS OPTIONAL
 * @return int 0 on success, negative error codes
 */
int vmo_punch_range(vm_object *vmo, unsigned long start, unsigned long length)
{
    return vmo_purge_pages(start, start + length, PURGE_SHOULD_FREE, nullptr, vmo);
}

static int vmo_punch_range(vm_object *vmo, unsigned long start, unsigned long length,
                           unsigned int flags)
{
    return vmo_purge_pages(start, start + length, PURGE_SHOULD_FREE | flags, nullptr, vmo);
}

/**
 * @brief Truncates the VMO.
 *
 * @param vmo The VMO to be truncated.
 * @param size The desired size.
 * @param flags Flags; Valid flags:
 *        VMO_TRUNCATE_DONT_PUNCH: Don't bother punching the range if we truncate
 *                                 the file to a smaller size.
 * @return 0 on success, negative error codes.
 */
int vmo_truncate(vm_object *vmo, unsigned long size, unsigned long flags)
{
    scoped_mutex g{vmo->page_lock};
    const auto original_size = size;

    size = cul::align_up2(size, PAGE_SIZE);
    // printk("New size: %lx\n", size);

    if (!(flags & VMO_TRUNCATE_DONT_PUNCH))
    {
        auto truncating_down = size < vmo->size;

        if (truncating_down)
        {
            auto hole_start = size;
            auto hole_length = vmo->size - size;
            /* We've already locked up there */
            vmo_punch_range(vmo, hole_start, hole_length, PURGE_DO_NOT_LOCK);
        }
    }

    auto last_page_off = cul::align_down2(original_size, PAGE_SIZE);
    auto ex = vmo->vm_pages.get(last_page_off >> PAGE_SHIFT);
    struct page *last_page = (struct page *) ex.value_or((unsigned long) nullptr);

    if (last_page)
    {
        // Truncate the last page by zeroing the trailing bytes
        auto to_zero = size - original_size;
        const auto page_off = original_size & (PAGE_SIZE - 1);
        memset((unsigned char *) PAGE_TO_VIRT(last_page) + page_off, 0, to_zero);
    }

    vmo->size = size;

    return 0;
}
