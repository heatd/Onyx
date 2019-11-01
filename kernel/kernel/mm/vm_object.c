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

#include <libdict/rb_tree.h>

#include <sys/mman.h>

static int page_cmp(const void* k1, const void* k2)
{
	if(k1 == k2)
		return 0;

        return (unsigned long) k1 < (unsigned long) k2 ? -1 : 1; 
}

struct vm_object *vmo_create(size_t size, void *priv)
{
	struct vm_object *vmo = zalloc(sizeof(*vmo));
	if(!vmo)
		return NULL;

	/* Default to backed */
	vmo->type = VMO_BACKED;
	vmo->size = size;
	vmo->priv = priv;
	vmo->refcount = 1;
	vmo->pages = rb_tree_new(page_cmp);
	if(!vmo->pages)
	{
		free(vmo);
		return NULL;
	}

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
	vmo->type = VMO_ANON;

	return vmo;
}

/*
 * Populates a VMO
*/

struct page *vmo_populate(struct vm_object *vmo, size_t off)
{
	MUST_HOLD_LOCK(&vmo->page_lock);
	assert(vmo->commit != NULL);

	struct page *page = vmo->commit(off, vmo);
	if(!page)
	{
		printk("vmo commit failed\n");
		return NULL;
	}

	page->off = off;

	dict_insert_result res = rb_tree_insert(vmo->pages, (void *) page->off);
	if(!res.inserted)
	{
		printk("rb_tree_insert failed\n");
		free_page(page);
		return NULL;
	}

	if(vmo->flags & VMO_FLAG_LOCK_FUTURE_PAGES)
		page->flags |= PAGE_FLAG_LOCKED;

	*res.datum_ptr = page;

	return page;
}

struct page *vmo_get(struct vm_object *vmo, size_t off, bool may_populate)
{
	struct page *p = NULL;
	assert(off < vmo->size);

	spin_lock_preempt(&vmo->page_lock);

	void **pp = rb_tree_search(vmo->pages, (const void *) off);
	
	if(pp)
	{
		p = *pp;
	}

	if(!p && may_populate)
		p = vmo_populate(vmo, off);
	spin_unlock_preempt(&vmo->page_lock);

	return p;
}

void vmo_rb_delete_func(void *key, void *data)
{
	struct page *p = data;

	free_page(p);
}

int vmo_fork_pages(struct vm_object *vmo)
{
	size_t pages = vm_align_size_to_pages(vmo->size);
	if(!pages)
		return 0;
	
	rb_itor *it = rb_itor_new(vmo->pages);
	if(!it)
		return -1;

	rb_tree *new_tree = rb_tree_new(page_cmp);
	if(!new_tree)
	{
		free(it);
		return -1;
	}

	spin_lock(&vmo->page_lock);

	bool node_valid = rb_itor_first(it);

	while(node_valid)
	{
		struct page *old_p = *rb_itor_datum(it);
		/* No need to zero since it's being overwritten anyway */
		struct page *p = alloc_page(0);
		
		if(!p)
		{
			rb_tree_free(new_tree, vmo_rb_delete_func);
			rb_itor_free(it);
			spin_unlock(&vmo->page_lock);
			return -1;
		}
	
		p->off = old_p->off;
		copy_page_to_page(page_to_phys(p), page_to_phys(old_p));

		dict_insert_result res = rb_tree_insert(new_tree, (void *) p->off);
		if(!res.inserted)
		{
			free_page(p);
			rb_tree_free(new_tree, vmo_rb_delete_func);
			rb_itor_free(it);
			spin_unlock(&vmo->page_lock);
			return -1;
		}

		*res.datum_ptr = p;
		node_valid = rb_itor_next(it);
	}

	vmo->pages = new_tree;

	spin_unlock(&vmo->page_lock);

	return 0;
}

void vmo_unref_list(struct list *l)
{
	for(struct list_node *n = l->head; n != NULL; n = n->next)
	{
		struct page *p = n->ptr;
		free_page(p);
	}
}

struct vm_object *vmo_fork(struct vm_object *vmo, bool shared, struct vm_region *reg)
{
	struct vm_object *new_vmo;
	if(!shared)
	{
		new_vmo = vmo_create(vmo->size, vmo->priv);
		if(!new_vmo)
			return NULL;
		memcpy(new_vmo, vmo, sizeof(*new_vmo));
		/* Locks are not inherited */
		new_vmo->flags &= ~(VMO_FLAG_LOCK_FUTURE_PAGES);
		new_vmo->refcount = 1;
		new_vmo->mappings.head = new_vmo->mappings.tail = NULL;
		new_vmo->prev_private = new_vmo->next_private = NULL;
		new_vmo->forked_from = vmo;

		spin_lock(&vmo->page_lock);
		if(vmo_fork_pages(new_vmo) < 0)
		{
			free(new_vmo);
			spin_unlock(&vmo->page_lock);
			return NULL;
		}

		spin_unlock(&vmo->page_lock);
	}
	else
	{
		if(__sync_add_and_fetch(&vmo->refcount, 1) == 1)
			return NULL;
		if(vmo_assign_mapping(vmo, reg) < 0)
		{
			vmo_unref(vmo);
			return NULL;
		}

		return vmo;
	}
	
	return new_vmo;
}

static void vmo_rollback_pages(struct page *begin, struct page *end, struct vm_object *vmo)
{
	struct page *p = begin;
	while(p != end)
	{
		rb_tree_remove(vmo->pages, (const void *) p->off);
		p = p->next_un.next_allocation;
	}
}

int vmo_prefault(struct vm_object *vmo, size_t size, size_t offset)
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
		
		dict_insert_result res = rb_tree_insert(vmo->pages, (void *) _p->off);
		if(!res.inserted)
		{
			vmo_rollback_pages(p, _p, vmo);
			free_pages(p);
			return -1;
		}

		*res.datum_ptr = _p;
		_p = _p->next_un.next_allocation;
	}

	return 0;
}

void vmo_destroy(struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	rb_tree_free(vmo->pages, vmo_rb_delete_func);

	spin_unlock(&vmo->page_lock);

	free(vmo);
}

int vmo_add_page(size_t off, struct page *p, struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	p->off = off;

	dict_insert_result res = rb_tree_insert(vmo->pages, (void *) p->off);
	if(!res.inserted)
	{
		spin_unlock(&vmo->page_lock);
		return -1;
	}

	*res.datum_ptr = p;

	spin_unlock(&vmo->page_lock);

	return 0;
}

bool vmo_unref(struct vm_object *vmo)
{
	if(__sync_sub_and_fetch(&vmo->refcount, 1) == 0)
	{
		//printk("Deleting vmo %p with size %lx\n", vmo, vmo->size);
		vmo_destroy(vmo);
		return true;
	}
	else
	{
		//printk("Unrefed vmo %p with size %lx\n", vmo, vmo->size);
	}

	return false;
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


int vmo_purge_pages(size_t lower_bound, size_t upper_bound, unsigned int flags,
			  struct vm_object *second, struct vm_object *vmo)
{
	struct rb_itor *it = rb_itor_new(vmo->pages);
	if(!it)
		return -1;

	spin_lock(&vmo->page_lock);

	bool should_free = flags & PURGE_SHOULD_FREE;
	bool exclusive = flags & PURGE_EXCLUDE;

	assert(!(should_free && second != NULL));

	bool (*compare_function)(size_t, size_t, size_t) = is_included;

	if(exclusive)
		compare_function = is_excluded;

	bool node_valid = rb_itor_first(it);

	while(node_valid)
	{
		struct page *p = *rb_itor_datum(it);
		if(compare_function(lower_bound, upper_bound, p->off))
		{

			rb_itor_remove(it);
			node_valid = rb_itor_search_ge(it, (const void *) p->off);

			struct page *old_p = p;

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
			node_valid = rb_itor_next(it);
		}
	}

	spin_unlock(&vmo->page_lock);

	return 0;
}

int vmo_resize(size_t new_size, struct vm_object *vmo)
{
	bool needs_to_purge = new_size < vmo->size;
	vmo->size = new_size;
	if(needs_to_purge)
		vmo_purge_pages(0, new_size, PURGE_SHOULD_FREE | PURGE_EXCLUDE, NULL, vmo);

	return 0;
}

bool vm_update_off(const void *key, void *page, void *of)
{
	struct page *p = page;
	p->off -= (size_t) of;
	return true;
}

void vmo_update_offsets(size_t off, struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	rb_tree_traverse(vmo->pages, vm_update_off, (void *) off);

	spin_unlock(&vmo->page_lock);
}

struct vm_object *vmo_create_copy(struct vm_object *vmo)
{
	struct vm_object *copy = memdup(vmo, sizeof(*vmo));

	if(!copy)
		return NULL;
	copy->flags &= ~(VMO_FLAG_LOCK_FUTURE_PAGES);
	
	bool file = copy->type == VMO_BACKED && copy->ino;
	
	if(file)
		object_ref(&copy->ino->i_object);
	
	return copy;
}

struct vm_object *vmo_split(size_t split_point, size_t hole_size, struct vm_object *vmo)
{
	struct vm_object *second_vmo = vmo_create_copy(vmo);

	if(!second_vmo)
		return NULL;

	second_vmo->size -= split_point + hole_size;
	second_vmo->pages = rb_tree_new(page_cmp);
	second_vmo->mappings.head = second_vmo->mappings.tail = NULL;
	if(second_vmo->ino) object_ref(&second_vmo->ino->i_object);

	if(!second_vmo->pages)
	{
		free(second_vmo);
		return NULL;
	}

	unsigned long max = hole_size + split_point;

	if(vmo_purge_pages(split_point, max, PURGE_SHOULD_FREE, NULL, vmo) < 0 ||
	   vmo_purge_pages(max, vmo->size, 0, second_vmo, vmo) < 0)
	{
		if(second_vmo->ino)
			object_unref(&second_vmo->ino->i_object);
		rb_tree_free(second_vmo->pages, vmo_rb_delete_func);
		free(second_vmo);
		return NULL;
	}

	vmo_update_offsets(split_point + hole_size, second_vmo);

	vmo->size -= hole_size + second_vmo->size;

	return second_vmo;
}

void vmo_sanity_check(struct vm_object *vmo)
{
	spin_lock(&vmo->page_lock);

	struct rb_itor *it = rb_itor_new(vmo->pages);
	assert(it != NULL);
	bool node_valid = rb_itor_next(it);
	while(node_valid)
	{
		struct page *p = *rb_itor_datum(it);
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

	vmo->size -= off;
}

void vmo_ref(struct vm_object *vmo)
{
	__sync_add_and_fetch(&vmo->refcount, 1);
}

int vmo_assign_mapping(struct vm_object *vmo, struct vm_region *region)
{
	spin_lock(&vmo->mapping_lock);

	int ret = list_add_node(&vmo->mappings, region);

	spin_unlock(&vmo->mapping_lock);
	
	return ret;
}

bool vmo_is_shared(struct vm_object *vmo)
{
	return vmo->refcount != 1;
}
