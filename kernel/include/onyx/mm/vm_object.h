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

#ifdef __cplusplus

/**
 * @brief Punches a hole into the given vmo, using the optional parameter `func` as a free page callback.
 * 
 * @param vmo The VMO
 * @param start The start of the hole
 * @param length The length of the hole
 * @param func The function callback for freeing pages, IS OPTIONAL
 * @return int 0 on success, negative error codes
 */
int vmo_punch_range(vm_object *vmo, unsigned long start, unsigned long length);

#define VMO_TRUNCATE_DONT_PUNCH           (1 << 0)

int vmo_truncate(vm_object *vmo, unsigned long size, unsigned long flags);

#endif

struct vm_region;

void vmo_assign_mapping(struct vm_object *vmo, struct vm_region *region);
void vmo_remove_mapping(struct vm_object *vmo, struct vm_region *region);
struct vm_object *vmo_create(size_t size, void *priv);
struct vm_object *vmo_create_phys(size_t size);

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
vmo_status_t vmo_get(struct vm_object *vmo, size_t off, unsigned int flags, struct page **ppage);


struct vm_object *vmo_fork(struct vm_object *vmo, bool shared, struct vm_region *reg);
int vmo_prefault(struct vm_object *vmo, size_t size, size_t offset);
bool vmo_unref(struct vm_object *vmo);
int vmo_resize(size_t new_size, struct vm_object *vmo);
void vmo_update_offsets(size_t off, struct vm_object *vmo);
struct vm_object *vmo_split(size_t split_point, size_t hole_size, struct vm_object *vmo);
void vmo_sanity_check(struct vm_object *vmo);
void vmo_destroy(struct vm_object *vmo);
int vmo_add_page(size_t off, struct page *p, struct vm_object *vmo);
void vmo_ref(struct vm_object *vmo);
bool vmo_is_shared(struct vm_object *vmo);
void vmo_do_cow(struct vm_object *vmo, struct vm_object *target);
vmo_status_t vmo_get_cow_page(struct vm_object *vmo, size_t off, struct page **ppage);
void vmo_uncow(struct vm_object *vmo);
struct page *vmo_cow_on_page(struct vm_object *vmo, size_t off);

static inline bool vmo_on_cow(struct vm_object *vmo)
{
	return vmo->cow_clone != NULL;
}

#endif
