/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_MM_VM_OBJECT_H
#define _ONYX_MM_VM_OBJECT_H

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

#define VMO_FLAG_LOCK_FUTURE_PAGES		(1 << 0)
#define VMO_FLAG_DEVICE_MAPPING         (1 << 1)
struct vm_object
{
	enum vmo_type type;
	size_t size;
	unsigned long flags;

	rb_tree *pages;

	/* Points to (or is) private data that may be needed by the backer of this VM */
	void *priv;

	/* Commits a page */
	struct page * (*commit)(size_t off, struct vm_object *vmo);

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
extern "C" {
#endif

struct vm_region;

void vmo_assign_mapping(struct vm_object *vmo, struct vm_region *region);
void vmo_remove_mapping(struct vm_object *vmo, struct vm_region *region);
struct vm_object *vmo_create(size_t size, void *priv);
struct page *vmo_populate(struct vm_object *vmo, size_t off);
struct vm_object *vmo_create_phys(size_t size);

#define VMO_GET_MAY_POPULATE                     (1 << 0)
#define VMO_GET_MAY_NOT_IMPLICIT_COW                 (1 << 1)

struct page *vmo_get(struct vm_object *vmo, size_t off, unsigned int flags);
struct vm_object *vmo_fork(struct vm_object *vmo, bool shared, struct vm_region *reg);
int vmo_prefault(struct vm_object *vmo, size_t size, size_t offset);
bool vmo_unref(struct vm_object *vmo);
int vmo_resize(size_t new_size, struct vm_object *vmo);
void vmo_update_offsets(size_t off, struct vm_object *vmo);
struct vm_object *vmo_split(size_t split_point, size_t hole_size, struct vm_object *vmo);
void vmo_truncate_beginning_and_resize(size_t off, struct vm_object *vmo);
void vmo_sanity_check(struct vm_object *vmo);
void vmo_destroy(struct vm_object *vmo);
int vmo_add_page(size_t off, struct page *p, struct vm_object *vmo);
void vmo_ref(struct vm_object *vmo);
bool vmo_is_shared(struct vm_object *vmo);
void vmo_do_cow(struct vm_object *vmo, struct vm_object *target);
struct page *vmo_get_cow_page(struct vm_object *vmo, size_t off);
void vmo_uncow(struct vm_object *vmo);
struct page *vmo_cow_on_page(struct vm_object *vmo, size_t off);

static inline bool vmo_on_cow(struct vm_object *vmo)
{
	return vmo->cow_clone != NULL;
}

#ifdef __cplusplus
}
#endif

#endif
