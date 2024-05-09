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

vm_object::vm_object() : size{0}, flags{0}, priv{nullptr}, ops{nullptr}, ino{nullptr}, refcount{1}
{
    interval_tree_root_init(&mappings);
    spinlock_init(&page_lock);
    spinlock_init(&mapping_lock);
    INIT_LIST_HEAD(&private_list);
    spinlock_init(&private_lock);
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
    return vmo;
}

/**
 * @brief Insert a page into the vmo
 *
 * @param off Offset into the vmo, in bytes
 * @param page struct page to insert
 * @return 0 on success, negative error codes (ENOMEM)
 */
struct page *vm_object::insert_page_unlocked(unsigned long off, struct page *page)
{
    auto ex = vm_pages.get(off >> PAGE_SHIFT);
    if (ex.has_value())
    {
        page_unref(page);
        page = (struct page *) ex.value();
        page_ref(page);
        return page;
    }

    if (int st0 = vm_pages.store(off >> PAGE_SHIFT, (unsigned long) page); st0 < 0)
        return nullptr;

    page->pageoff = off >> PAGE_SHIFT;
    page->owner = this;

    return page;
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
    struct page *p = nullptr;

    scoped_lock g{vmo->page_lock};

#if 1
    if (vmo->ino && !(vmo->flags & VMO_FLAG_DEVICE_MAPPING))
        vmo->size = cul::max(vmo->size, cul::align_up2(off + 1, PAGE_SIZE));
#endif

    if (off >= vmo->size)
        return VMO_STATUS_BUS_ERROR;

    auto ex = vmo->vm_pages.get(off >> PAGE_SHIFT);
    if (ex.has_value())
        p = (struct page *) ex.value();

    if (!p)
        st = VMO_STATUS_NON_EXISTENT;

    if (st == VMO_STATUS_OK)
    {
        page_pin(p);
        *ppage = p;
    }

    return st;
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
    scoped_lock g{vmo->page_lock};
    if (!vmo->insert_page_unlocked(off, p))
        return -ENOMEM;
    return 0;
}

/**
 * @brief Maps a page into the VMO.
 *
 * @param off Offset of the page inside the VMO.
 * @param p Page to be mapped on the vmo.
 * @param vmo The VMO.
 * @return 0 on success, -1 on failure to map.
 */
struct page *vmo_add_page_safe(size_t off, struct page *p, vm_object *vmo)
{
    scoped_lock g{vmo->page_lock};
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
    if (__atomic_sub_fetch(&vmo->refcount, 1, __ATOMIC_RELEASE) == 0)
    {
        vmo_destroy(vmo);
        return true;
    }

    return false;
}

static int vm_obj_get_pages(struct vm_object *obj, unsigned long start, unsigned long end,
                            struct page **batch, int batchlen)
{
    int batchidx = 0;
    scoped_lock g{obj->page_lock};
    radix_tree::cursor cursor = radix_tree::cursor::from_range(&obj->vm_pages, start, end);

    while (!cursor.is_end())
    {
        if (!batchlen--)
            break;
        struct page *page = (struct page *) cursor.get();
        batch[batchidx++] = page;
        page_ref(page);
        cursor.advance();
    }

    return batchidx;
}

static void vm_obj_truncate_out(struct vm_object *obj, struct page *const *batch, int batchlen)
{
    spin_lock(&obj->page_lock);
    for (int i = 0; i < batchlen; i++)
    {
        struct page *pg = batch[i];
        /* Not sure if we're doing the correct exclusion between truncation... */
        CHECK(pg->owner == obj);
        int st = obj->vm_pages.store(pg->pageoff, 0);
        CHECK(st == 0);
    }

    spin_unlock(&obj->page_lock);
}

#define VMOBJ_TRUNCATE_BATCH_SIZE 16
static int vmo_purge_pages(unsigned long start, unsigned long end,
                           struct vm_object *vmo) NO_THREAD_SAFETY_ANALYSIS
{
    /* TSA: Clang cries when looking at the batch locking code. It is provably correct */
    struct page *pagebatch[VMOBJ_TRUNCATE_BATCH_SIZE];
    int found = 0;
    /* We deal with pages, not offsets */
    start >>= PAGE_SHIFT;
    end >>= PAGE_SHIFT;
    end -= 1;
    while ((found = vm_obj_get_pages(vmo, start, end, pagebatch, VMOBJ_TRUNCATE_BATCH_SIZE)) > 0)
    {
        /* Start the next iteration from the following page */
        start = pagebatch[found - 1]->pageoff + 1;

        /* Lock all the pages (in a batch), then wait for writeback etc, then truncate them from the
         * page cache, then unlock. This requires minimal locking. Locking the page prevents races
         * between truncation and other operations that require a stable reference to the
         * pagecache (e.g mapping, writing and reading from disk). */
        for (int i = 0; i < found; i++)
        {
            lock_page(pagebatch[i]);
            page_wait_writeback(pagebatch[i]);
        }

        vm_obj_truncate_out(vmo, pagebatch, found);

        for (int i = 0; i < found; i++)
        {
            /* Page has been truncated from the page cache, no writeback is ongoing, now unlock
             * and free. */
            struct page *old_p = pagebatch[i];
            vmo->unmap_page(old_p->pageoff << PAGE_SHIFT);
            unlock_page(old_p);
            /* Unref it twice, once for the vm_obj_get_pages, and another for the page cache
             * reference */
            page_unref(old_p);
            dec_page_stat(old_p, NR_FILE);
            if (!vmo->ops->free_page)
                free_page(old_p);
            else
                vmo->ops->free_page(vmo, old_p);
        }
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
    scoped_lock g{mapping_lock};
    struct vm_area_struct *vma;
    for_intervals_in_range(&mappings, vma, struct vm_area_struct, vm_objhead, offset, offset)
    {
        const off_t vmregion_end = vma->vm_offset + (vma_pages(vma) << PAGE_SHIFT);
        DCHECK(vma->vm_objhead.start <= offset && vma->vm_objhead.end > offset);
        DCHECK(vma->vm_offset <= (off_t) offset && vmregion_end > (off_t) offset);
        DCHECK(vma->vm_offset == (off_t) vma->vm_objhead.start &&
               vma->vm_objhead.end == vma->vm_offset + vma->vm_end - vma->vm_start);
        vm_mmu_unmap(vma->vm_mm, (void *) (vma->vm_start + offset - vma->vm_offset), 1);
    }
}

/**
 * @brief Increments the reference counter on the VMO.
 *
 * @param vmo The VMO.
 */
void vmo_ref(vm_object *vmo)
{
    __atomic_add_fetch(&vmo->refcount, 1, __ATOMIC_ACQUIRE);
}

/**
 * @brief Registers a new mapping on the VMO.
 *
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_assign_mapping(vm_object *vmo, vm_area_struct *region)
{
    scoped_lock g{vmo->mapping_lock};
    interval_tree_insert(&vmo->mappings, &region->vm_objhead);
}

/**
 * @brief Removes a mapping on the VMO.
 *
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_remove_mapping(vm_object *vmo, vm_area_struct *region)
{
    scoped_lock g{vmo->mapping_lock};
    interval_tree_remove(&vmo->mappings, &region->vm_objhead);
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
    return vmo_purge_pages(start, start + length, vmo);
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
    scoped_lock g{vmo->page_lock};
    const auto original_size = size;

    size = cul::align_up2(size, PAGE_SIZE);
    // printk("New size: %lx\n", size);

    if (!(flags & VMO_TRUNCATE_DONT_PUNCH))
    {
        auto truncating_down = size < vmo->size;

        if (truncating_down)
        {
            auto hole_start = size;
            unsigned long hole_end = vmo->size;
            /* Ugh, this is ugly and possibly unsafe. We've already locked up there... */
            g.unlock();
            vmo_purge_pages(hole_start, cul::align_up2(hole_end, PAGE_SHIFT), vmo);
            g.lock();
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

vm_object::~vm_object()
{
    vmo_truncate(this, 0, 0);
}
