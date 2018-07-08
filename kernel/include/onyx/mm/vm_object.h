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

struct vmo_file_mapping
{
	struct file_description *fd;
	off_t off;
};

struct vm_object
{
	size_t size;

	struct page *page_list;

	/* Points to private data that may be needed by the backer of this VM */
	void *priv;

	/* Commits a page */
	struct page * (*commit)(size_t off, struct vm_object *vmo);

	/* VM objects hold a pointer to their mapping(s) */
	struct vm_entry *mappings;

	/* We also hold a pointer to their COW clones */
	struct vm_object *cow_clone_parent, *cow_clone_child;

	union
	{
		struct vmo_file_mapping fmap;
	} u_info;

	struct spinlock page_lock;

	struct spinlock mapping_lock;
};

struct vm_object *vmo_create(size_t size, void *priv);
struct page *vmo_populate(struct vm_object *vmo, off_t off);
struct vm_object *vmo_create_phys(size_t size);
struct page *vmo_get(struct vm_object *vmo, off_t off, bool may_populate);
struct vm_object *vmo_fork(struct vm_object *vmo);

#endif