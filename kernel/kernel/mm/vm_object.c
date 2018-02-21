/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/mm/vm_object.h>
#include <onyx/page.h>
#include <onyx/vmm.h>
#include <onyx/utils.h>
#include <onyx/atomic.h>
#include <onyx/ioctx.h>

#include <sys/mman.h>

struct vm_object *vmo_create(size_t size, void *priv)
{
	struct vm_object *vmo = zalloc(sizeof(*vmo));
	if(!vmo)
		return NULL;
	vmo->size = size;
	vmo->priv = priv;

	return vmo;
}

/*
 * Commits a page for a VMO backed by physical memory
*/
struct page *vmo_commit_phys_page(size_t off, struct vm_object *vmo)
{
	struct page *p = get_phys_page();
	if(!p)
		return NULL;
	p->off = off;
	return p;
}

/*
 * Creates a VMO with a physical memory backing(instead of a file backing, etc)
*/
struct vm_object *vmo_create_phys(size_t size)
{
	struct vm_object *vmo = vmo_create(size, NULL);
	if(!vmo)
		return NULL;
	vmo->commit = vmo_commit_phys_page;

	return vmo;
}

/*
 * Populates a VMO
*/

struct page *vmo_populate(struct vm_object *vmo, off_t off)
{
	struct page *page = vmo->commit(off, vmo);
	if(!page)
		return NULL;

	page->off = off;
	acquire_spinlock(&vmo->page_lock);

	if(!vmo->page_list)
		vmo->page_list = page;
	else
	{
		struct page *p = vmo->page_list;
		while(p->next_un.next_virtual_region)
			p = p->next_un.next_virtual_region;
		p->next_un.next_virtual_region = page;
	}

	release_spinlock(&vmo->page_lock);

	return page;
}

struct page *vmo_get(struct vm_object *vmo, off_t off, bool may_populate)
{
	struct page *p = NULL;
	acquire_spinlock(&vmo->page_lock);

	struct page *l = vmo->page_list;

	while(l)
	{
		if(l->off == off)
		{
			p = l;
			break;
		}
		l = l->next_un.next_virtual_region;
	}
	release_spinlock(&vmo->page_lock);

	if(!p && may_populate)
		p = vmo_populate(vmo, off);
	return p;
}

int vmo_fork_pages(struct vm_object *vmo)
{
	size_t pages = vmm_align_size_to_pages(vmo->size);
	if(!pages)
		return 0;
	
	acquire_spinlock(&vmo->page_lock);

	struct page *list = NULL;
	struct page *last = NULL;
	struct page *old_entry = vmo->page_list;

	while(old_entry)
	{
		struct page *p = get_phys_page();
		
		/* TODO: Free */
		if(!p)
		{
			release_spinlock(&vmo->page_lock);
			return -1;
		}

		if(!list)
			list = p;
		else
			last->next_un.next_virtual_region = p;
		p->off = old_entry->off;
		copy_page_to_page(p->paddr, old_entry->paddr);

		old_entry = old_entry->next_un.next_virtual_region;
		last = p;
	}

	atomic_set((unsigned long *) &vmo->page_list, (unsigned long) list);
	release_spinlock(&vmo->page_lock);

	return 0;
}

struct vm_object *vmo_fork(struct vm_object *vmo)
{
	bool shared, file;
	struct vm_object *new_vmo = vmo_create(vmo->size, vmo->priv);
	if(!new_vmo)
		return NULL;
	memcpy(new_vmo, vmo, sizeof(*new_vmo));

	shared = is_mapping_shared(new_vmo->mappings);
	file = is_file_backed(new_vmo->mappings);
	if(!shared)
	{
		acquire_spinlock(&vmo->page_lock);
		if(vmo_fork_pages(new_vmo) < 0)
		{
			free(new_vmo);
			release_spinlock(&vmo->page_lock);
			return NULL;
		}
		release_spinlock(&vmo->page_lock);
	}

	if(file)
		new_vmo->u_info.fmap.fd->refcount++;
	
	return new_vmo;
}
