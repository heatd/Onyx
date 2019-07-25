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
#include <libdict/rb_tree.h>

enum vmo_type
{
	VMO_ANON = 0,
	VMO_BACKED = 1
};

struct vm_object
{
	enum vmo_type type;
	size_t size;

	rb_tree *pages;

	/* Points to private data that may be needed by the backer of this VM */
	void *priv;

	/* Commits a page */
	struct page * (*commit)(size_t off, struct vm_object *vmo);

	/* VM objects hold a pointer to their mapping(s) */
	struct list mappings;

	/* We also hold a pointer to their COW clones */
	struct vm_object *cow_clone_parent, *cow_clone_child;

	struct inode *ino;
	struct spinlock page_lock;

	struct spinlock mapping_lock;

	unsigned long refcount;
	struct vm_object *forked_from;

	struct vm_object *prev_private, *next_private;
};

#ifdef __cplusplus
extern "C" {
#endif

struct vm_region;

int vmo_assign_mapping(struct vm_object *vmo, struct vm_region *region);
struct vm_object *vmo_create(size_t size, void *priv);
struct page *vmo_populate(struct vm_object *vmo, size_t off);
struct vm_object *vmo_create_phys(size_t size);
struct page *vmo_get(struct vm_object *vmo, size_t off, bool may_populate);
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

#ifdef __cplusplus
}
#endif

#endif
