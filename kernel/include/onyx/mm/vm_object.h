/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_MM_VM_OBJECT_H
#define _ONYX_MM_VM_OBJECT_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>

#include <onyx/page.h>
#include <onyx/list.h>
#include <onyx/mutex.h>

#include <libdict/rb_tree.h>

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
	switch(st)
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

#define VMO_FLAG_LOCK_FUTURE_PAGES		(1 << 0)
#define VMO_FLAG_DEVICE_MAPPING         (1 << 1)

/**
 * @brief Represents a generic VM object, that may have backing or may just be anonymous.
 * The VM subsystem works with these objects, and each VM region points to a 
 * VM object(this is not entirely true, since MMIO mappings don't have associated
 * struct pages nor VM objects).
 */
struct vm_object
{
	enum vmo_type type;
	size_t size;
	unsigned long flags;

	rb_tree *pages;

	/* Points to (or is) private data that may be needed by the backer of this VM */
	void *priv;

	const struct vm_object_ops *ops;

	/* VM objects hold pointers to their mapping(s) */
	struct list_head mappings;

	/* We also hold a pointer to their COW clones */
	struct vm_object *cow_clone;

	struct inode *ino;
	struct mutex page_lock;

	struct spinlock mapping_lock;

	unsigned long refcount;
	struct vm_object *forked_from;

	struct vm_object *prev_private, *next_private;
};

/**
 * @brief Punches a hole into the given vmo, using the optional parameter `func` as a free page callback.
 * 
 * @param vmo The VMO
 * @param start The start of the hole
 * @param length The length of the hole
 * @param func The function callback for freeing pages, IS OPTIONAL
 * @return 0 on success, negative error codes
 */
int vmo_punch_range(vm_object *vmo, unsigned long start, unsigned long length);

#define VMO_TRUNCATE_DONT_PUNCH           (1 << 0)

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

struct vm_region;

/**
 * @brief Registers a new mapping on the VMO.
 * 
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_assign_mapping(vm_object *vmo, vm_region *region);

/**
 * @brief Removes a mapping on the VMO.
 * 
 * @param vmo The target VMO.
 * @param region The mapping's region.
 */
void vmo_remove_mapping(vm_object *vmo, vm_region *region);

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

#define VMO_GET_MAY_POPULATE                         (1 << 0)
#define VMO_GET_MAY_NOT_IMPLICIT_COW                 (1 << 1)

/**
 * @brief Fetch a page from a VM object
 * 
 * @param vmo 
 * @param off The offset inside the vm object
 * @param flags The valid flags are defined above (may populate, may not implicit cow)
 * @param ppage Pointer to where the struct page will be placed 
 * @return The vm_status_t of the request
 */
vmo_status_t vmo_get(vm_object *vmo, size_t off, unsigned int flags, struct page **ppage);

/**
 * @brief Forks the VMO, performing any COW tricks that may be required.
 * 
 * @param vmo The VMO to be forked.
 * @param shared True if the region is shared. This makes it skip all the work.
 * @param reg The new forked region. 
 * @return The vm object to be refed and used by the new region.
 */
vm_object *vmo_fork(vm_object *vmo, bool shared, struct vm_region *reg);

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

/**
 * @brief Does copy-on-write for MAP_PRIVATE mappings.
 * 
 * @param vmo The new VMO. 
 * @param target The copy-on-write master.
 */
void vmo_do_cow(vm_object *vmo, vm_object *target);

/**
 * @brief Gets a page from the copy-on-write master.
 * 
 * @param vmo The VMO.
 * @param off Offset of the page.
 * @param ppage Pointer to a page * where the result will be placed.
 * @return Status of the vmo get(). 
 */
vmo_status_t vmo_get_cow_page(vm_object *vmo, size_t off, page **ppage);

/**
 * @brief Un-COW's a VMO.
 * 
 * @param vmo The VMO to be uncowed.
 */
void vmo_uncow(vm_object *vmo);

/**
 * @brief Does copy-on-write of a page that is present and just got written to.
 * 
 * @param vmo The VMO.
 * @param off Offset of the page.
 * @return The struct page of the new copied-to page.
 */
struct page *vmo_cow_on_page(vm_object *vmo, size_t off);

/**
 * @brief Determines whether the vmo is a COW copy.
 * 
 * @param vmo The VMO.
 * @return True if it is, false if not.
 */
static inline bool vmo_on_cow(vm_object *vmo)
{
	return vmo->cow_clone != NULL;
}

#endif
