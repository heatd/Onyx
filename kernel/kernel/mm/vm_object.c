/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <assert.h>

#include <onyx/mm/vm_object.h>
#include <onyx/page.h>
#include <onyx/vm.h>
#include <onyx/utils.h>
#include <onyx/atomic.h>
#include <onyx/ioctx.h>
#include <onyx/file.h>
#include <onyx/panic.h>

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
	struct page *p = alloc_page(0);
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
	assert(vmo->commit != NULL);

	struct page *page = vmo->commit(off, vmo);
	if(!page)
		return NULL;

	page->off = off;
	spin_lock(&vmo->page_lock);

	if(!vmo->page_list)
		vmo->page_list = page;
	else
	{
		struct page *p = vmo->page_list;
		while(p->next_un.next_virtual_region)
			p = p->next_un.next_virtual_region;
		p->next_un.next_virtual_region = page;
	}

	spin_unlock(&vmo->page_lock);

	return page;
}

struct page *vmo_get(struct vm_object *vmo, off_t off, bool may_populate)
{
	struct page *p = NULL;
	spin_lock(&vmo->page_lock);

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
	spin_unlock(&vmo->page_lock);

	if(!p && may_populate)
		p = vmo_populate(vmo, off);
	return p;
}

int vmo_fork_pages(struct vm_object *vmo)
{
	size_t pages = vm_align_size_to_pages(vmo->size);
	if(!pages)
		return 0;
	
	spin_lock(&vmo->page_lock);

	struct page *list = NULL;
	struct page *last = NULL;
	struct page *old_entry = vmo->page_list;

	while(old_entry)
	{
		/* No need to zero since it's being overwritten anyway */
		struct page *p = alloc_page(0);
		
		/* TODO: Free */
		if(!p)
		{
			spin_unlock(&vmo->page_lock);
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
	spin_unlock(&vmo->page_lock);

	return 0;
}

struct vm_object *vmo_fork(struct vm_object *vmo)
{
	bool shared, file;
	struct vm_object *new_vmo = vmo_create(vmo->size, vmo->priv);
	if(!new_vmo)
		return NULL;
	memcpy(new_vmo, vmo, sizeof(*new_vmo));

	/* TODO: Fix shared vmo forks */
	shared = is_mapping_shared(new_vmo->mappings);
	file = is_file_backed(new_vmo->mappings);
	if(!shared)
	{
		spin_lock(&vmo->page_lock);
		if(vmo_fork_pages(new_vmo) < 0)
		{
			free(new_vmo);
			spin_unlock(&vmo->page_lock);
			return NULL;
		}

		spin_unlock(&vmo->page_lock);
	}

	if(file)
		new_vmo->u_info.fmap.fd->refcount++;
	
	return new_vmo;
}

int vmo_prefault(struct vm_object *vmo, size_t size, off_t offset)
{
	size_t pages = vm_align_size_to_pages(size);

	struct page *p = alloc_pages(pages, 0);
	if(!p)
	{
		printk("alloc_pages failed: could not allocate %lu pages!\n", pages);
		return -1;
	}

	struct page *_p = p;
	for(size_t i = 0; i < pages; i++, offset += PAGE_SIZE)
	{
		_p->off = offset;
		_p = _p->next_un.next_allocation;
	}

	vmo->page_list = p;

	if(vm_flush(vmo->mappings) < 0)
		return -1;
	return 0;
}

void __vmo_unmap(struct vm_object *vmo)
{	
	for(struct page *p = vmo->page_list; p != NULL;
		p = p->next_un.next_virtual_region)
	{
		paging_unmap((void *) (vmo->mappings->base + p->off));
	}
}

void vmo_destroy(struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	/* Unmap the mapped pages */
	__vmo_unmap(vmo);

	if(vmo->page_list) free_pages(vmo->page_list);
	vmo->page_list = NULL;

	if(is_file_backed(vmo->mappings))
	{
		fd_unref(vmo->u_info.fmap.fd);
	}

	spin_unlock(&vmo->page_lock);

	free(vmo);
}

void vmo_add_page(off_t off, struct page *p, struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	p->off = off;

	struct page **pp = &vmo->page_list;
	while(*pp)
		pp = &(*pp)->next_un.next_virtual_region;

	*pp = p;

	spin_unlock(&vmo->page_lock);
}

void vmo_unref(struct vm_object *vmo)
{
	/* For now, unref just destroys the object since vmo sharing is not
	 * implemented yet.
	*/
	vmo_destroy(vmo);
}

static inline bool is_included(size_t lower, size_t upper, size_t x)
{
	if(x >= lower && x < upper)
		return true;
	return false;
}

static inline bool is_excluded(size_t lower, size_t upper, size_t x)
{
	if(x < lower || x > upper)
		return true;
	return false;
}


#define PURGE_SHOULD_FREE	(1 << 0)
#define	PURGE_EXCLUDE		(1 << 1)


void vmo_purge_pages(size_t lower_bound, size_t upper_bound, unsigned int flags,
			  struct vm_object *second, struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	struct page *before = NULL;
	struct page *p = vmo->page_list;

	bool should_free = flags & PURGE_SHOULD_FREE;
	bool exclusive = flags & PURGE_EXCLUDE;

	assert(!(should_free && second != NULL));

	bool (*compare_function)(size_t, size_t, size_t) = is_included;

	if(exclusive)
		compare_function = is_excluded;

	while(p != NULL)
	{
		if(compare_function(lower_bound, upper_bound, p->off))
		{
			if(!before)
			{
				vmo->page_list = p->next_un.next_virtual_region;
			}
			else
			{
				before->next_un.next_virtual_region = p->next_un.next_virtual_region;
			}

			struct page *old_p = p;
			p = p->next_un.next_virtual_region;

			old_p->next_un.next_virtual_region = NULL;

			/* TODO: Add a virtual function to do this */
			if(should_free)
			{
				free_page(old_p);
			}

			if(second)
				vmo_add_page(old_p->off, old_p, second);
		}
		else
		{
			before = p;
			p = p->next_un.next_virtual_region;
		}
	}

	spin_unlock(&vmo->page_lock);
}

int vmo_resize(size_t new_size, struct vm_object *vmo)
{
	vmo->size = new_size;
	vmo_purge_pages(0, new_size, PURGE_SHOULD_FREE | PURGE_EXCLUDE, NULL, vmo);

	return 0;
}

void vmo_update_offsets(size_t off, struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	for(struct page *p = vmo->page_list; p != NULL; p = p->next_un.next_virtual_region)
	{
		p->off -= off;
	}

	spin_unlock(&vmo->page_lock);
}

struct vm_object *vmo_create_copy(struct vm_object *vmo)
{
	struct vm_object *copy = memdup(vmo, sizeof(*vmo));

	if(!copy)
		return NULL;
	
	bool file = is_file_backed(vmo->mappings);
	
	if(file)
		copy->u_info.fmap.fd->refcount++;
	
	return copy;
}

struct vm_object *vmo_split(size_t split_point, size_t hole_size, struct vm_object *vmo)
{
	struct vm_object *second_vmo = vmo_create_copy(vmo);

	if(!second_vmo)
		return NULL;

	second_vmo->size -= split_point + hole_size;
	second_vmo->page_list = NULL;
	if(is_file_backed(second_vmo->mappings))
		second_vmo->u_info.fmap.off += split_point + hole_size;

	unsigned long max = hole_size + split_point;

	vmo_purge_pages(split_point, max, PURGE_SHOULD_FREE, NULL, vmo);
	vmo_purge_pages(max, vmo->size, 0, second_vmo, vmo);
	vmo_update_offsets(split_point + hole_size, second_vmo);

	vmo->size -= hole_size + second_vmo->size;

	return second_vmo;
}

void vmo_sanity_check(struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	for(struct page *p = vmo->page_list; p != NULL; p = p->next_un.next_virtual_region)
	{
		if(p->off > vmo->size)
		{
			printk("Bad vmobject: p->off > nr_pages << PAGE_SHIFT.\n");
			printk("struct page: %p\n", p);
			printk("Offset: %lx\n", p->off);
			printk("Size: %lx\n", vmo->size);
			panic("bad vmobject");
		}

		if(p->ref == 0)
		{
			printk("Bad vmobject:: p->ref == 0.\n");
			printk("struct page: %p\n", p);
			panic("bad vmobject");
		}
	}	

	spin_unlock(&vmo->page_lock);
}

void vmo_truncate_beginning_and_resize(size_t off, struct vm_object *vmo)
{
	vmo_purge_pages(0, off, PURGE_SHOULD_FREE, NULL, vmo);
	vmo_update_offsets(off, vmo);

	if(is_file_backed(vmo->mappings))
		vmo->u_info.fmap.off += off;
	vmo->size -= off;
}