/*
 * Copyright (c) 2018 - 2024 Pedro Falcato
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

#include <onyx/interval_tree.h>
#include <onyx/list.h>
#include <onyx/mutex.h>
#include <onyx/page.h>

#ifdef __cplusplus
#include <onyx/radix.h>
#endif

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
    size_t size;
    unsigned long flags;

    /* sigh... */
#ifdef __cplusplus
    radix_tree vm_pages;
#else
    struct __dummy_radix
    {
        void *ptr;
        int order;
    } __dummy_vm_pages;
#endif

    /* Points to (or is) private data that may be needed by the backer of this VM */
    void *priv;

    const struct vm_object_ops *ops;

    /* VM objects hold pointers to their mapping(s) */
    struct interval_tree_root mappings;

    struct inode *ino;
    struct spinlock page_lock;
    struct spinlock mapping_lock;

    unsigned long refcount;

    /* See fs/buffer.cpp for example usage of these struct members */
    struct spinlock private_lock;
    struct list_head private_list;

#ifdef __cplusplus

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
        scoped_lock g{mapping_lock};
        struct vm_area_struct *vma;

        for_intervals_in_range(&mappings, vma, struct vm_area_struct, vm_objhead, 0, -1UL)
        {
            if (!c(vma))
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
    struct page *insert_page_unlocked(unsigned long off, struct page *page);

    template <typename Callable>
    bool for_every_page(Callable c)
    {
        return vm_pages.for_every_entry([&](rt_entry_t entry, unsigned long idx) -> bool {
            return c((struct page *) entry, idx << PAGE_SHIFT);
        });
    }
#endif
};

__BEGIN_CDECLS

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
int vmo_punch_range(struct vm_object *vmo, unsigned long start, unsigned long length);

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
int vmo_truncate(struct vm_object *vmo, unsigned long size, unsigned long flags);

struct vm_area_struct;

/**
 * @brief Registers a new mapping on the VMO.
 *
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_assign_mapping(struct vm_object *vmo, struct vm_area_struct *region);

/**
 * @brief Removes a mapping on the VMO.
 *
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_remove_mapping(struct vm_object *vmo, struct vm_area_struct *region);

/**
 * @brief Creates a new VMO.
 *
 * @param size The size of the VMO.
 * @param priv Pointer to private, optional.
 * @return A pointer to the new VMO, or NULL if out of memory.
 */
struct vm_object *vmo_create(size_t size, void *priv);

/**
 * @brief Creates a new anonymously backed VMO.
 *
 * @param size The size of the VMO.
 *
 * @return A pointer to the new VMO, or NULL if out of memory.
 */
struct vm_object *vmo_create_phys(size_t size);

/**
 * @brief Fetch a page from a VM object
 *
 * @param vmo
 * @param off The offset inside the vm object
 * @param flags The valid flags are defined above (may populate)
 * @param ppage Pointer to where the struct page will be placed
 * @return The vm_status_t of the request
 */
vmo_status_t vmo_get(struct vm_object *vmo, size_t off, unsigned int flags, struct page **ppage);

/**
 * @brief Releases the vmo, and destroys it if it was the last reference.
 *
 * @param vmo The VMO to be unrefed.
 * @return True if it was destroyed, false if it's still alive.
 */
bool vmo_unref(struct vm_object *vmo);

/**
 * @brief Destroys the VMO, disregarding any refcount.
 * This should not be called arbitrarily and only in cases where it's certain
 * that we hold the only reference.
 *
 * @param vmo The VMO to be destroyed.
 */
void vmo_destroy(struct vm_object *vmo);

/**
 * @brief Maps a page into the VMO.
 *
 * @param off Offset of the page inside the VMO.
 * @param p Page to be mapped on the vmo.
 * @param vmo The VMO.
 * @return 0 on success, -1 on failure to map.
 */
int vmo_add_page(size_t off, struct page *p, struct vm_object *vmo);

/**
 * @brief Increments the reference counter on the VMO.
 *
 * @param vmo The VMO.
 */
void vmo_ref(struct vm_object *vmo);

/**
 * @brief Determines whether or not the VMO is currently being shared.
 *
 * @param vmo The VMO.
 * @return True if it is, false if not.
 */
bool vmo_is_shared(struct vm_object *vmo);

/**
 * @brief Maps a page into the VMO.
 *
 * @param off Offset of the page inside the VMO.
 * @param p Page to be mapped on the vmo.
 * @param vmo The VMO.
 * @return 0 on success, -1 on failure to map.
 */
struct page *vmo_add_page_safe(size_t off, struct page *p, struct vm_object *vmo);

__END_CDECLS

#endif
