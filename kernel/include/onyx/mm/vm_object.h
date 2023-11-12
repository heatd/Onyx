/*
 * Copyright (c) 2018 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_MM_VM_OBJECT_H
#define _ONYX_MM_VM_OBJECT_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <onyx/list.h>
#include <onyx/mutex.h>
#include <onyx/page.h>
#include <onyx/radix.h>

enum vmo_type
{
    VMO_ANON = 0,
    VMO_BACKED = 1
};

typedef enum vmo_status
{
    VMO_STATUS_OK = 0,
    VMO_STATUS_BUS_ERROR,
    VMO_STATUS_OUT_OF_MEM,
    VMO_STATUS_NON_EXISTENT
} vmo_status_t;

static inline int vmo_status_to_errno(vmo_status_t st)
{
    switch (st)
    {
        case VMO_STATUS_OK:
            return 0;
        case VMO_STATUS_BUS_ERROR:
            return EIO;
        case VMO_STATUS_OUT_OF_MEM:
            return ENOMEM;
        default:
            return EIO;
    }
}

struct page;
struct vm_object;
struct vm_object_ops
{
    vmo_status_t (*commit)(struct vm_object *vmo, size_t offset, struct page **ppage);
    void (*free_page)(struct vm_object *vmo, struct page *page);
};

#define VMO_FLAG_LOCK_FUTURE_PAGES (1 << 0)
#define VMO_FLAG_DEVICE_MAPPING    (1 << 1)

/**
 * @brief Represents a generic VM object, that may have backing or may just be anonymous.
 * The VM subsystem works with these objects, and each VM region points to a
 * VM object(this is not entirely true, since MMIO mappings don't have associated
 * struct pages nor VM objects).
 */
struct vm_object
{
    vmo_type type{VMO_ANON};
    size_t size{0};
    unsigned long flags{0};

    radix_tree vm_pages;

    /* Points to (or is) private data that may be needed by the backer of this VM */
    void *priv{nullptr};

    const struct vm_object_ops *ops{nullptr};

    /* VM objects hold pointers to their mapping(s) */
    struct list_head mappings;

    struct inode *ino{nullptr};
    struct mutex page_lock;

    struct mutex mapping_lock;

    unsigned long refcount{1};
    struct vm_object *forked_from{nullptr};

    struct vm_object *prev_private{nullptr}, *next_private{nullptr};

    vm_object();
    ~vm_object();

    /**
     * @brief Unmaps a single page from every mapping
     *
     * @param offset Offset of the page
     */
    void unmap_page(size_t offset);

    template <typename Callable>
    bool for_every_mapping(Callable c)
    {
        scoped_mutex g{mapping_lock};

        list_for_every (&mappings)
        {
            auto reg = container_of(l, vm_area_struct, vm_objhead);
            if (!c(reg))
                return false;
        }

        return true;
    }

    /**
     * @brief Insert a page into the vmo
     *
     * @param off Offset into the vmo, in bytes
     * @param page struct page to insert
     * @return 0 on success, negative error codes (ENOMEM)
     */
    int insert_page_unlocked(unsigned long off, struct page *page);

    template <typename Callable>
    bool for_every_page(Callable c)
    {
        return vm_pages.for_every_entry([&](rt_entry_t entry, unsigned long idx) -> bool {
            return c((struct page *) entry, idx << PAGE_SHIFT);
        });
    }
};

/**
 * @brief Punches a hole into the given vmo, using the optional parameter `func` as a free page
 * callback.
 *
 * @param vmo The VMO
 * @param start The start of the hole
 * @param length The length of the hole
 * @param func The function callback for freeing pages, IS OPTIONAL
 * @return 0 on success, negative error codes
 */
int vmo_punch_range(vm_object *vmo, unsigned long start, unsigned long length);

#define VMO_TRUNCATE_DONT_PUNCH (1 << 0)

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
int vmo_truncate(vm_object *vmo, unsigned long size, unsigned long flags);

struct vm_area_struct;

/**
 * @brief Registers a new mapping on the VMO.
 *
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_assign_mapping(vm_object *vmo, vm_area_struct *region);

/**
 * @brief Removes a mapping on the VMO.
 *
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_remove_mapping(vm_object *vmo, vm_area_struct *region);

/**
 * @brief Creates a new VMO.
 *
 * @param size The size of the VMO.
 * @param priv Pointer to private, optional.
 * @return A pointer to the new VMO, or NULL if out of memory.
 */
vm_object *vmo_create(size_t size, void *priv);

/**
 * @brief Creates a new anonymously backed VMO.
 *
 * @param size The size of the VMO.
 *
 * @return A pointer to the new VMO, or NULL if out of memory.
 */
vm_object *vmo_create_phys(size_t size);

/**
 * @brief Fetch a page from a VM object
 *
 * @param vmo
 * @param off The offset inside the vm object
 * @param flags The valid flags are defined above (may populate)
 * @param ppage Pointer to where the struct page will be placed
 * @return The vm_status_t of the request
 */
vmo_status_t vmo_get(vm_object *vmo, size_t off, unsigned int flags, struct page **ppage);

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
int vmo_prefault(vm_object *vmo, size_t size, size_t offset);

/**
 * @brief Releases the vmo, and destroys it if it was the last reference.
 *
 * @param vmo The VMO to be unrefed.
 * @return True if it was destroyed, false if it's still alive.
 */
bool vmo_unref(vm_object *vmo);

// TODO: This should be removed and replaced by vmo_truncate.
int vmo_resize(size_t new_size, vm_object *vmo);

/**
 * @brief Creates a new vmo and moves all pages in [split_point, split_point + hole_size] to it.
 *
 * @param split_point The start of the split point.
 * @param hole_size The size of the hole.
 * @param vmo The VMO to be split.
 * @return The new vmo populated with all pre-existing vmo pages in the range.
 */
vm_object *vmo_split(size_t split_point, size_t hole_size, vm_object *vmo);

/**
 * @brief Does a brief sanity check on the VMO.
 * This is only present for debugging purposes and should not be called.
 *
 * @param vmo The VMO.
 */
void vmo_sanity_check(vm_object *vmo);

/**
 * @brief Destroys the VMO, disregarding any refcount.
 * This should not be called arbitrarily and only in cases where it's certain
 * that we hold the only reference.
 *
 * @param vmo The VMO to be destroyed.
 */
void vmo_destroy(vm_object *vmo);

/**
 * @brief Maps a page into the VMO.
 *
 * @param off Offset of the page inside the VMO.
 * @param p Page to be mapped on the vmo.
 * @param vmo The VMO.
 * @return 0 on success, -1 on failure to map.
 */
int vmo_add_page(size_t off, page *p, vm_object *vmo);

/**
 * @brief Increments the reference counter on the VMO.
 *
 * @param vmo The VMO.
 */
void vmo_ref(vm_object *vmo);

/**
 * @brief Determines whether or not the VMO is currently being shared.
 *
 * @param vmo The VMO.
 * @return True if it is, false if not.
 */
bool vmo_is_shared(vm_object *vmo);

#endif
