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
	INIT_LIST_HEAD(&vmo->mappings);
	vmo->pages = rb_tree_new(page_cmp);
	mutex_init(&vmo->page_lock);

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
#include <onyx/timer.h>

struct page *vmo_populate(struct vm_object *vmo, size_t off)
{
	MUST_HOLD_MUTEX(&vmo->page_lock);
	assert(vmo->commit != NULL);

	//hrtime_t s = get_main_clock()->get_ns();
	struct page *page = vmo->commit(off, vmo);
	if(!page)
	{
		return NULL;
	}

	//hrtime_t end = get_main_clock()->get_ns();
	dict_insert_result res = rb_tree_insert(vmo->pages, (void *) off);
	if(!res.inserted)
	{
		free_page(page);
		return NULL;
	}

	if(vmo->flags & VMO_FLAG_LOCK_FUTURE_PAGES)
		page->flags |= PAGE_FLAG_LOCKED;

	*res.datum_ptr = page;

	return page;
}

struct page *vmo_get(struct vm_object *vmo, size_t off, unsigned int flags)
{
	bool may_populate = flags & VMO_GET_MAY_POPULATE;
	bool may_not_implicit_cow = flags & VMO_GET_MAY_NOT_IMPLICIT_COW;
	bool is_cow = vmo->cow_clone != NULL;
 
	struct page *p = NULL;
	
	if(vmo->ino && !(vmo->flags & VMO_FLAG_DEVICE_MAPPING))
		vmo->size = vmo->ino->i_size;

	/* TODO: Add a way to spit out error codes */
	if(off >= vmo->size)
	{
		return NULL;
	}

	mutex_lock(&vmo->page_lock);

	void **pp = rb_tree_search(vmo->pages, (const void *) off);
	
	if(pp)
	{
		p = *pp;
	}

	if(!p && is_cow && !may_not_implicit_cow)
	{
		struct page *new_page = alloc_page(PAGE_ALLOC_NO_ZERO);
		if(!new_page)
		{
			mutex_unlock(&vmo->page_lock);
			return NULL;
		}

		size_t vmo_off = (off_t) vmo->priv;

		//printk("clone size: %lx\n", vmo->cow_clone->ino->i_size);
		struct page *old_page = vmo_get(vmo->cow_clone, off + vmo_off, flags);
		if(!old_page)
		{
			//printk("failed\n");
			free_page(new_page);
			mutex_unlock(&vmo->page_lock);
			return NULL;
		}

		copy_page_to_page(page_to_phys(new_page), page_to_phys(old_page));

		page_unpin(old_page);

		dict_insert_result res = rb_tree_insert(vmo->pages, (void *) off);
		if(!res.inserted)
		{
			free_page(new_page);
			mutex_unlock(&vmo->page_lock);
			return NULL;
		}

		*res.datum_ptr = new_page;

		p = new_page;
	}

	if(!p && may_populate)
		p = vmo_populate(vmo, off);
	

	if(p)
	{
		page_pin(p);
	}

	mutex_unlock(&vmo->page_lock);

	return p;
}

void vmo_rb_delete_func(void *key, void *data)
{
	struct page *p = data;

	free_page(p);
}

int vmo_fork_pages(struct vm_object *vmo)
{
	size_t pages = vm_size_to_pages(vmo->size);
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

	mutex_lock(&vmo->page_lock);

	bool node_valid = rb_itor_first(it);

	while(node_valid)
	{
		struct page *old_p = *rb_itor_datum(it);
		size_t off = (size_t) rb_itor_key(it);
	
		dict_insert_result res = rb_tree_insert(new_tree, (void *) off);
		if(!res.inserted)
		{
			rb_tree_free(new_tree, vmo_rb_delete_func);
			rb_itor_free(it);
			mutex_unlock(&vmo->page_lock);
			return -1;
		}

		page_ref(old_p);

		*res.datum_ptr = old_p;
		node_valid = rb_itor_next(it);
	}

	vmo->pages = new_tree;

	mutex_unlock(&vmo->page_lock);

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

	if(shared)
	{
		/* Shared mappings have the peculiarity of just being a atomic add to the refc,
		 * and an append to a mappings list. Therefore, we don't need to do anything here,
		 * since it will be handled by each vm region's forking(fork_vm_region, mm/vm.c).
		 */

		return vmo;
	}

	/* Private mappings require a new copy of the vmo to be created, so we can fork it
	 * correctly. */

	new_vmo = vmo_create(vmo->size, vmo->priv);
	if(!new_vmo)
		return NULL;

	new_vmo->flags = vmo->flags;
	/* Locks are not inherited */
	new_vmo->flags &= ~(VMO_FLAG_LOCK_FUTURE_PAGES);
	new_vmo->prev_private = new_vmo->next_private = NULL;
	new_vmo->forked_from = vmo;
	new_vmo->ino = vmo->ino;
	new_vmo->commit = vmo->commit;
	new_vmo->type = vmo->type;
	new_vmo->priv = vmo->priv;
	
	/* We're setting pages to the old vmo's pages so vmo_fork_pages can use them.
	 * In reality, vmo_fork_pages will just iterate through the old tree and create a copy
	 * of it.
	 */
	new_vmo->pages = vmo->pages;
	new_vmo->cow_clone = vmo->cow_clone;

	if(new_vmo->cow_clone) vmo_ref(new_vmo->cow_clone);

	mutex_lock(&vmo->page_lock);
	if(vmo_fork_pages(new_vmo) < 0)
	{
		free(new_vmo);
		mutex_unlock(&vmo->page_lock);
		return NULL;
	}

	mutex_unlock(&vmo->page_lock);
	
	return new_vmo;
}

static void vmo_rollback_pages(struct page *begin, struct page *end, struct vm_object *vmo)
{
	struct page *p = begin;
	size_t off = 0;
	while(p != end)
	{
		rb_tree_remove(vmo->pages, (const void *) off);
		p = p->next_un.next_allocation;
		off += PAGE_SIZE;
	}
}

int vmo_prefault(struct vm_object *vmo, size_t size, size_t offset)
{
	size_t pages = vm_size_to_pages(size);

	struct page *p = alloc_pages(pages, 0);
	if(!p)
	{
		printk("alloc_pages failed: could not allocate %lu pages!\n", pages);
		return -1;
	}

	struct page *_p = p;
	for(size_t i = 0; i < pages; i++, offset += PAGE_SIZE)
	{		
		dict_insert_result res = rb_tree_insert(vmo->pages, (void *) offset);
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
	mutex_lock(&vmo->page_lock);

	if(vmo->cow_clone) vmo_unref(vmo);

	rb_tree_free(vmo->pages, vmo_rb_delete_func);

	mutex_unlock(&vmo->page_lock);

	free(vmo);
}

int vmo_add_page(size_t off, struct page *p, struct vm_object *vmo)
{
	mutex_lock(&vmo->page_lock);

	dict_insert_result res = rb_tree_insert(vmo->pages, (void *) off);
	if(!res.inserted)
	{
		mutex_unlock(&vmo->page_lock);
		return -1;
	}

	*res.datum_ptr = p;

	mutex_unlock(&vmo->page_lock);

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
		//printk("Vmo ino: %p Refs: %lu\n", vmo->ino, vmo->refcount);
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

	mutex_lock(&vmo->page_lock);

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
		size_t off = (size_t) rb_itor_key(it);
	
		if(compare_function(lower_bound, upper_bound, off))
		{

			rb_itor_remove(it);
			node_valid = rb_itor_search_ge(it, (const void *) off);

			struct page *old_p = p;

			old_p->next_un.next_virtual_region = NULL;

			/* TODO: Add a virtual function to do this */
			if(should_free)
			{
				free_page(old_p);
			}

			if(second)
				vmo_add_page(off, old_p, second);
		}
		else
		{
			node_valid = rb_itor_next(it);
		}
	}

	mutex_unlock(&vmo->page_lock);

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
	/* FIXME: This doesn't work */
	struct page *p = page;
	(void) p;
	return true;
}

void vmo_update_offsets(size_t off, struct vm_object *vmo)
{
	mutex_lock(&vmo->page_lock);

	rb_tree_traverse(vmo->pages, vm_update_off, (void *) off);

	mutex_unlock(&vmo->page_lock);
}

struct vm_object *vmo_create_copy(struct vm_object *vmo)
{
	struct vm_object *copy = memdup(vmo, sizeof(*vmo));

	if(!copy)
		return NULL;
	
	mutex_init(&copy->page_lock);
	copy->flags &= ~(VMO_FLAG_LOCK_FUTURE_PAGES);
	if(copy->cow_clone)    vmo_ref(copy->cow_clone);
	
	return copy;
}

struct vm_object *vmo_split(size_t split_point, size_t hole_size, struct vm_object *vmo)
{
	struct vm_object *second_vmo = vmo_create_copy(vmo);

	if(!second_vmo)
		return NULL;

	second_vmo->size -= split_point + hole_size;
	second_vmo->pages = rb_tree_new(page_cmp);
	INIT_LIST_HEAD(&second_vmo->mappings);
	if(second_vmo->ino) inode_ref(second_vmo->ino);

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
			inode_unref(second_vmo->ino);
		rb_tree_free(second_vmo->pages, vmo_rb_delete_func);
		free(second_vmo);
		return NULL;
	}

	vmo->size -= hole_size + second_vmo->size;

	return second_vmo;
}

void vmo_sanity_check(struct vm_object *vmo)
{
	mutex_lock(&vmo->page_lock);

	struct rb_itor *it = rb_itor_new(vmo->pages);
	assert(it != NULL);
	bool node_valid = rb_itor_next(it);
	while(node_valid)
	{
		struct page *p = *rb_itor_datum(it);
		size_t poff = (size_t) rb_itor_key(it);
		if(poff > vmo->size)
		{
			printk("Bad vmobject: p->off > nr_pages << PAGE_SHIFT.\n");
			printk("struct page: %p\n", p);
			printk("Offset: %lx\n", poff);
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

	mutex_unlock(&vmo->page_lock);
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

void vmo_assign_mapping(struct vm_object *vmo, struct vm_region *region)
{
	spin_lock(&vmo->mapping_lock);

	list_add_tail(&region->vmo_head, &vmo->mappings);

	spin_unlock(&vmo->mapping_lock);
}

void vmo_remove_mapping(struct vm_object *vmo, struct vm_region *region)
{
	spin_lock(&vmo->mapping_lock);

	list_remove(&region->vmo_head);

	spin_unlock(&vmo->mapping_lock);
}

bool vmo_is_shared(struct vm_object *vmo)
{
	return vmo->refcount != 1;
}

void vmo_do_cow(struct vm_object *vmo, struct vm_object *target)
{
	assert(vmo->cow_clone == NULL);
	assert(target != NULL);
	vmo_ref(target);
	vmo->cow_clone = target;
}

struct page *vmo_get_cow_page(struct vm_object *vmo, size_t off)
{
	size_t vmo_off = (off_t) vmo->priv;
	struct page *p = vmo_get(vmo->cow_clone, vmo_off + off, VMO_GET_MAY_POPULATE);

	if(!p)
		return NULL;
	
	/* Don't forget to ref the page! */
	page_ref(p);
	
	if(vmo_add_page(off, p, vmo) < 0)
		page_unpin(p);

	return p;
}

void vmo_uncow(struct vm_object *vmo)
{
	vmo_unref(vmo->cow_clone);
	vmo->cow_clone = NULL;
}

struct page *vmo_cow_on_page(struct vm_object *vmo, size_t off)
{
	mutex_lock(&vmo->page_lock);
	
	void **datum = rb_tree_search(vmo->pages, (void *) off);
	
	if(datum == NULL)
		panic("Fatal COW bug - page not found in VMO");

	struct page *old_page = *datum;

	struct page *new_page = alloc_page(PAGE_ALLOC_NO_ZERO);
	if(!new_page)
		goto out_error;
	
	copy_page_to_page(page_to_phys(new_page), page_to_phys(old_page));

	*datum = new_page;
	
	page_pin(new_page);

	mutex_unlock(&vmo->page_lock);

	return new_page;
out_error:
	mutex_unlock(&vmo->page_lock);
	return NULL;
}
