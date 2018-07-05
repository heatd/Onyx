/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <onyx/file.h>
#include <onyx/paging.h>
#include <onyx/page.h>
#include <onyx/vmm.h>
#include <onyx/panic.h>
#include <onyx/compiler.h>
#include <onyx/process.h>
#include <onyx/log.h>
#include <onyx/dev.h>
#include <onyx/random.h>
#include <onyx/sysfs.h>
#include <onyx/vfs.h>
#include <onyx/spinlock.h>
#include <onyx/atomic.h>
#include <onyx/utils.h>

#include <onyx/mm/vm_object.h>

#include <onyx/vm_layout.h>

#include <sys/mman.h>

#define VM_COOKIE_INTACT		0xDEADBEEFDEADBEEF
typedef struct avl_node
{
	struct avl_node *left, *right;
	uintptr_t key;
	uintptr_t end;
	uintptr_t cookie;
	struct vm_entry *data;
} avl_node_t;

static spinlock_t kernel_vm_spl;
bool is_initialized = false;
static bool enable_aslr = true;

uintptr_t high_half 		= arch_high_half;
uintptr_t low_half_max 		= arch_low_half_max;
uintptr_t low_half_min 		= arch_low_half_min;

/* These addresses are either absolute, or offsets, depending on the architecture.
 * The corresponding arch/ code is responsible for patching these up using
 * vm_update_addresses.
*/
uintptr_t vmalloc_space 	= arch_vmalloc_off;
uintptr_t kstacks_addr	 	= arch_kstacks_off;
uintptr_t heap_addr		= arch_heap_off;

static avl_node_t *kernel_tree = NULL;

int setup_vmregion_backing(void *vaddr, size_t pages, bool is_file_backed);
int populate_shared_mapping(void *page, struct file_description *fd,
	struct vm_entry *entry, size_t nr_pages);

int imax(int x, int y)
{
	return x > y ? x : y;
}

uintptr_t max(uintptr_t x, uintptr_t y)
{
	return x > y ? x : y;
}

uintptr_t min(uintptr_t x, uintptr_t y)
{
	return x < y ? x : y;
}

int avl_get_height(avl_node_t *ptr)
{
	int height_left = 0, height_right = 0;
	if(ptr->left) height_left = -avl_get_height(ptr->left) + 1;
	if(ptr->right) height_right = avl_get_height(ptr->right) + 1;

	return imax(height_right, height_left);
}

void avl_rotate_left_to_right(avl_node_t **t)
{
	avl_node_t *a = *t;
	avl_node_t *b = a->left;
	avl_node_t *c = b->right;

	a->left = c->right;
	b->right = c->left;
	c->left = b;
	c->right = a;

	*t = c;
}

void avl_rotate_right_to_left(avl_node_t **t)
{
	avl_node_t *a = *t;
	avl_node_t *b = a->right;
	avl_node_t *c = b->left;
	a->right = c->left;
	b->left = c->right;
	c->right = b;
	c->left = a;
	*t = c;
}

void avl_rotate_left_to_left(avl_node_t **t)
{
	avl_node_t *a = *t;
	avl_node_t *b = a->left;
	a->left = b->right;
	b->right = a;

	*t = b;
}

void avl_rotate_right_to_right(avl_node_t **t)
{
	avl_node_t *a = *t;
	avl_node_t *b = a->right;
	a->right = b->left;
	b->left = a;

	*t = b;
}

void avl_balance_tree(avl_node_t **t)
{
	avl_node_t *ptr = *t;
	int height_left = 0, height_right = 0;

	if(ptr->left) height_left = avl_get_height(ptr->left);
	if(ptr->right) height_right = avl_get_height(ptr->right);

	if(height_right < -1 || height_right > 1)
		avl_balance_tree(&ptr->right);
	if(height_left < -1 || height_left > 1)
		avl_balance_tree(&ptr->left);

	height_right = 0;
	height_left = 0;

	if(ptr->left) height_left = -avl_get_height(ptr->left);
	if(ptr->right) height_right = avl_get_height(ptr->right);


	int balance = imax(height_right, height_left) + 1;

	if(balance < -1)
	{
		/* Left heavy */
		if(height_left < -1)
			avl_rotate_left_to_right(t);
		else
			avl_rotate_left_to_left(t);
	}
	else if(balance > 1)
	{
		if(height_right > 1)
			avl_rotate_right_to_left(t);
		else
			avl_rotate_right_to_right(t);
	}
}

bool avl_traverse(avl_node_t *tree, bool (*callback)(avl_node_t *node))
{
	if(tree->left)
	{
		/* return on true */
		if(avl_traverse(tree->left, callback) == true)
			return true;
	}

	if(tree->right)
	{
		/* return on true */
		if(avl_traverse(tree->right, callback) == true)
			return true;
	}

	return callback(tree);
}

static struct vm_entry *avl_insert_key(avl_node_t **t, uintptr_t key, uintptr_t end)
{
	avl_node_t **pp = t;
	while(*pp != NULL)
	{
		avl_node_t *ptr = *pp;
		if(key < ptr->key)
		{
			pp = &ptr->left;
		}
		else
		{
			pp = &ptr->right;
		}
	}
	
	*pp = malloc(sizeof(avl_node_t));
	if(!*pp)
		return NULL;
	memset(*pp, 0, sizeof(avl_node_t));
	avl_node_t *ptr = *pp;
	ptr->key = key;
	ptr->end = end;
	ptr->cookie = VM_COOKIE_INTACT;
	ptr->data = malloc(sizeof(struct vm_entry));
	if(!ptr->data)
	{
		free(*pp);
		*pp = NULL;
		return NULL;
	}
	memset(ptr->data, 0, sizeof(struct vm_entry));
	struct process *p = get_current_process();
	ptr->data->mm = p ? &p->address_space : NULL;
	
	
	if(key < high_half)
		avl_balance_tree(vmm_get_tree());
	else
		avl_balance_tree(&kernel_tree);
	return ptr->data;

}

static avl_node_t **avl_search_key(avl_node_t **t, uintptr_t key)
{
	if(!*t)
		return NULL;
	avl_node_t *ptr = *t;
	if(key == ptr->key)
		return t;
	if(key > ptr->key && key < ptr->key + ptr->end)
		return t;
	if(key < ptr->key)
		return avl_search_key(&ptr->left, key);
	else
		return avl_search_key(&ptr->right, key);
}

static int avl_delete_node(uintptr_t key)
{
	/* Try to find the node inside the tree */
	avl_node_t **n = avl_search_key(vmm_get_tree(), key);
	if(!n)
		return errno = ENOENT, -1;
	avl_node_t *ptr = *n;

	/* Free up all used memory and set *n to NULL */
	free(ptr->data);
	free(ptr);
	*n = NULL;

	return 0;
}

avl_node_t *avl_copy(avl_node_t *node, struct process *proc)
{
	avl_node_t *new = malloc(sizeof(avl_node_t));
	if(!new)
		return NULL;
	memcpy(new, node, sizeof(avl_node_t));

	new->data = memdup(new->data, sizeof(struct vm_entry));
	if(!new->data)
	{
		free(new);
		return NULL;
	}

	new->data->mm = proc ? &proc->address_space : NULL;

	if(new->left)
	{
		if(!(new->left = avl_copy(new->left, proc)))
		{
			free(new->data);
			free(new);
			return NULL;
		}
	}
	if(new->right)
	{
		if(!(new->right = avl_copy(new->right, proc)))
		{
			free(new->left->data);
			free(new->left);
			free(new->data);
			free(new);
			return NULL;
		}
	}

	return new;
}

void avl_clone(avl_node_t *node)
{
	if(node->left && node->left->key < high_half)
	{
		free(node->left);
		node->left = NULL;
	}
	if(node->right && node->right->key < high_half)
	{
		free(node->right);
		node->right = NULL;
	}
	if(node->left) avl_clone(node->left);
	if(node->right) avl_clone(node->right);
}

/* Destroy a tree recursively */
void avl_destroy_tree(avl_node_t *node)
{
	if(!node)
		return;
	if(node->left)
	{
		avl_destroy_tree(node->left);
		node->left = NULL;
	}
	if(node->right)
	{
		avl_destroy_tree(node->right);
		node->right = NULL;
	}
	/* First, unmap the range */
	if(node->data->mapping_type != MAP_SHARED)
		vmm_unmap_range((void*) node->key, node->data->pages);
	/* Now, free the node */
	free(node->data);
	free(node);
}

static avl_node_t **avl_min_value(avl_node_t *n)
{
	avl_node_t **pp = &n;
	while((*pp)->left)	pp = &(*pp)->left;

	return pp;
}

static avl_node_t *__avl_remove_node(avl_node_t **pp)
{
	avl_node_t *p = *pp;
	bool has_left = p->left != NULL;
	bool has_right = p->right != NULL;

	if(has_left && !has_right)
	{
		*pp = p->left;
		return p;
	}
	else if(has_right && !has_left)
	{
		*pp = p->right;
		return p;
	}
	else if(!has_left && !has_right)
	{
		*pp = NULL;
		return p;
	}

	/* Two children, find the inorder successor */

	avl_node_t **successor = avl_min_value(p->right);

	*pp = *successor;

	__avl_remove_node(successor);

	return p;
}

static avl_node_t *avl_remove_node(avl_node_t **tree, uintptr_t key)
{
	avl_node_t **pp = avl_search_key(tree, key);
	if(!pp)
		return NULL;
	avl_node_t *p = __avl_remove_node(pp);
	avl_balance_tree(tree);
	return p;
}

static inline void __vm_lock(bool kernel)
{
	if(kernel)
		acquire_spinlock(&kernel_vm_spl);
	else
		acquire_spinlock((spinlock_t*) &get_current_process()->address_space.vm_spl);
}

static inline void __vm_unlock(bool kernel)
{
	if(kernel)
		release_spinlock(&kernel_vm_spl);
	else
		release_spinlock((spinlock_t*) &get_current_process()->address_space.vm_spl);
}

static inline bool is_higher_half(void *address)
{
	return (uintptr_t) address > VM_HIGHER_HALF;
}

void vmm_init()
{
	paging_init();
	arch_vmm_init();
}

void heap_set_start(uintptr_t start);

void vmm_late_init(void)
{
	/* TODO: This should be arch specific stuff, move this to arch/ */
	uintptr_t heap_addr_no_aslr = heap_addr;

	kstacks_addr = vm_randomize_address(kstacks_addr, KSTACKS_ASLR_BITS);
	vmalloc_space = vm_randomize_address(vmalloc_space, VMALLOC_ASLR_BITS);
	heap_addr = vm_randomize_address(heap_addr, HEAP_ASLR_BITS);

	vmm_map_range((void*) heap_addr, vmm_align_size_to_pages(0x400000),
			VM_WRITE | VM_NOEXEC | VM_GLOBAL);
	heap_set_start(heap_addr);

	size_t heap_size = 0x200000000000 - (heap_addr - heap_addr_no_aslr);
	/* Start populating the address space */
	struct vm_entry *v = avl_insert_key(&kernel_tree,
		heap_addr, heap_size);
	if(!v)
	{
		panic("vmm: early boot oom");	
	}
	v->base = heap_addr;

	v->pages = heap_size / PAGE_SIZE;
	v->type = VM_TYPE_HEAP;
	v->rwx = VM_NOEXEC | VM_WRITE;

	v = avl_insert_key(&kernel_tree, KERNEL_VIRTUAL_BASE, UINT64_MAX - KERNEL_VIRTUAL_BASE);
	if(!v)
	{
		panic("vmm: early boot oom");	
	}
	v->base = KERNEL_VIRTUAL_BASE;
	v->pages = 0x80000000 / PAGE_SIZE;
	v->type = VM_TYPE_SHARED;
	v->rwx = 0;

	is_initialized = true;
}


struct page *vm_allocate_page(int opt, uintptr_t *page)
{
	if(pages_are_registered())
		return get_phys_page();
	else
	{
		*page = (uintptr_t) __alloc_page(opt);
		return NULL;
	}
}

struct page *vmm_map_range(void *range, size_t pages, uint64_t flags)
{
	bool kernel = is_higher_half(range);

	if(!kernel) __vm_lock(kernel);
	uintptr_t mem = (uintptr_t) range;
	struct page *page = NULL;
	struct page *ret = NULL;

	for (size_t pgs = 0; pgs < pages; pgs++)
	{
		uintptr_t raw_addr = 0;
		struct page *p = vm_allocate_page(0, &raw_addr);
		if(!pages_are_registered())
		{
			if(!raw_addr)
				goto out_of_mem;
		}
		else
		{
			if(!p)
				goto out_of_mem;
			if(!page)
				page = ret = p;
			else
			{
				page->next_un.next_virtual_region = p;
				page = p;
			}
			raw_addr = (uintptr_t) p->paddr;
		}

		if(!vm_map_page(NULL, mem, raw_addr, flags))
			goto out_of_mem;
		mem += PAGE_SIZE;
	}
	
	paging_invalidate(range, pages);
	if(!kernel) __vm_unlock(kernel);

	/* If pages aren't registered yet, retain the old
	 * behavior of returning the virtual address
	*/
	return pages_are_registered() ? ret : range;

	/* TODO: Free every page that was allocated */
out_of_mem:
	__vm_unlock(kernel);
	return NULL;
}

void vm_unmap_user(void *range, size_t pages)
{
	struct vm_entry *entry = vmm_is_mapped(range);
	assert(entry != NULL);
	uintptr_t mem = (uintptr_t) range;

	struct vm_object *vmo = entry->vmo;
	assert(vmo != NULL);

	acquire_spinlock(&vmo->page_lock);

	for(struct page *p = vmo->page_list; p != NULL;
		p = p->next_un.next_virtual_region)
	{

		paging_unmap((void *) (mem + p->off));
		if(page_decrement_refcount(p->paddr) == 0)
			__free_page(p->paddr);
	}
}

void vm_unmap_kernel(void *range, size_t pages)
{
	uintptr_t mem = (uintptr_t) range;
	for (size_t i = 0; i < pages; i++)
	{
		void *page = paging_unmap((void*) mem);
		if(page)
		{
			page_decrement_refcount(page);
			__free_page(page);
		}
		mem += 0x1000;
	}
}

void vmm_unmap_range(void *range, size_t pages)
{
	bool kernel = is_higher_half(range);

	__vm_lock(kernel);

	if(!kernel)
		vm_unmap_user(range, pages);
	else
		vm_unmap_kernel(range, pages);
	__vm_unlock(kernel);
}

void vmm_destroy_mappings(void *range, size_t pages)
{
	avl_node_t **tree = vmm_get_tree();
	uintptr_t p = (uintptr_t) range;
	uintptr_t end = p + (pages << PAGE_SHIFT);

	if(is_higher_half(range))
		tree = &kernel_tree;

	while(p != end)
	{
		avl_node_t **e = avl_search_key(tree, p);
		assert(e != NULL);
		avl_node_t *node = *e;
		assert(node != NULL);

		struct vm_entry *area = node->data;

		if(area->base == p && area->pages <= pages)
		{
			__avl_remove_node(e);
			avl_balance_tree(tree);
			p += node->end;
			pages -= area->pages;
			free(node->data);
			free(node);
		}
		else if(area->base < p && area->base + node->end == end)
		{
			area->pages -= (end - p) >> PAGE_SHIFT;
			node->end -= (end - p);
			p += (end - p);
			pages -= (end - p) >> PAGE_SHIFT;
			free(node->data);
			free(node);
		}
		else if(area->base < p && end < area->base + node->end)
		{
			uintptr_t new_area_end = area->base + node->end;
			uintptr_t new_area_start = end;
			node->end = p - area->base;
			area->pages = node->end >> PAGE_SHIFT;

			struct vm_entry *entry = avl_insert_key(tree,
				new_area_start, new_area_end - new_area_start);
			assert(entry != NULL);
			
			memcpy(entry, area, sizeof(struct vm_entry));
			entry->base = new_area_start;
			entry->pages = (new_area_end - new_area_start) >> PAGE_SHIFT;
			return;
		}
	}
}

void *__allocate_virt_address(uint64_t flags, size_t pages, uint32_t type,
	uint64_t prot, uintptr_t alignment)
{
	if(alignment == 0)
		alignment = 1;

	uintptr_t base_address = 0;
	/* TODO: Clean this up */
	switch(type)
	{
		case VM_TYPE_SHARED:
		case VM_TYPE_STACK:
		{
			if(!(flags & 1))
			{
				struct process *p = get_current_process();
				assert(p != NULL);
				if(!p->address_space.mmap_base)
					panic("mmap_base == 0");
				base_address = (uintptr_t) get_current_process()->
					address_space.mmap_base;
			}
			else
				base_address = kstacks_addr;
			break;
		}
		default:
		case VM_TYPE_REGULAR:
		{
			if(flags & 1)
				base_address = vmalloc_space;
			else
			{
				struct process *p = get_current_process();
				assert(p != NULL);
				if(!p->address_space.mmap_base)
					panic("mmap_base == 0");
				base_address = (uintptr_t) p->
					address_space.mmap_base;
			}
			break;
		}
	}
	
	/* TODO: Clean this up too */
	if(flags & 1)
	{
		avl_node_t **e = avl_search_key(&kernel_tree, base_address);
		while(e && *e)
		{
			avl_node_t *n = *e;
			/* Check for overflows while allocating a kernel address */
			if(add_check_overflow(base_address, n->data->pages * PAGE_SIZE, &base_address))
				return NULL;
			if(base_address % alignment)
			{
				if(add_check_overflow(base_address, alignment - (base_address % alignment), &base_address))
					return NULL;
			}
			e = avl_search_key(&kernel_tree, base_address);
			if(avl_search_key(&kernel_tree, base_address + pages * PAGE_SIZE) == NULL && !e)
				break;
		}
	}
	else
	{
		avl_node_t **e = avl_search_key(vmm_get_tree(), base_address);
		while(e && *e)
		{
again:
			;
			avl_node_t *n = *e;
			base_address += n->data->pages * PAGE_SIZE;
			if(base_address % alignment)
				base_address += alignment - (base_address % alignment);
			/* If the address has surpassed low_half_max, return NULL as we've ran out of 
			  virtual address space */
			if(base_address > low_half_max)
				return NULL;
			for(uintptr_t base = base_address; base < base_address + pages * PAGE_SIZE; base += PAGE_SIZE)
			{
				if((e = avl_search_key(vmm_get_tree(), base)))
					goto again;
			}
		}
	}

	return (void *) base_address;
}

void *vmm_allocate_virt_address(uint64_t flags, size_t pages, uint32_t type,
	uint64_t prot, uintptr_t alignment)
{
	/* Lock everything before allocating anything */
	bool allocating_kernel = true;
	if(flags & VM_ADDRESS_USER)
		allocating_kernel = false;
	__vm_lock(allocating_kernel);

	avl_node_t **tree = NULL;
	if(flags & 1)
		tree = &kernel_tree;
	else
		tree = vmm_get_tree();
	
	assert(tree != NULL);
	
	void *base_address = __allocate_virt_address(flags, pages, type, prot,
		alignment);
	if(!base_address)
		goto ret;

	struct vm_entry *en;

	/* TODO: Clean this up too */
	en = avl_insert_key(tree, (uintptr_t) base_address,
		pages * PAGE_SIZE);
	if(!en)
	{
		base_address = 0;
		errno = ENOMEM;
		goto ret;
	}
	en->rwx = (int) prot;
	en->type = type;
	en->pages = pages;
	en->base = (uintptr_t) base_address;

ret:

	/* Unlock and return */
	__vm_unlock(allocating_kernel);
	return (void*) base_address;
}

void *vmm_reserve_address(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	bool reserving_kernel = is_higher_half(addr);
	
	__vm_lock(reserving_kernel);
	/* BUG!: There's a bug right here, 
	 * vmm_is_mapped() is most likely not enough 
	*/
	if(vmm_is_mapped(addr))
	{
		__vm_unlock(reserving_kernel);
		errno = EINVAL;
		return NULL;
	}
	struct vm_entry *v;
	if((uintptr_t) addr >= high_half)
		v = avl_insert_key(&kernel_tree, (uintptr_t)addr, pages * PAGE_SIZE);
	else
		v = avl_insert_key(vmm_get_tree(), (uintptr_t)addr, pages * PAGE_SIZE);
	if(!v)
	{
		addr = NULL;
		errno = ENOMEM;
		goto return_;
	}
	v->base = (uintptr_t) addr;
	v->pages = pages;
	v->type = type;
	v->rwx = prot;
return_:
	__vm_unlock(reserving_kernel);
	return addr;
}

struct vm_entry *vmm_is_mapped(void *addr)
{
	avl_node_t **tree = vmm_get_tree();
	if(!tree)
		goto search_kernel;
	avl_node_t **e = avl_search_key(tree, (uintptr_t) addr);
	if(!e)
	{
search_kernel:
		e = avl_search_key(&kernel_tree, (uintptr_t) addr);
		if(!e)
			return NULL;
	}
	avl_node_t *n = *e;
	return n->data;
}

struct vm_entry *vm_find_region(void *addr)
{
	avl_node_t **tree = vmm_get_tree();
	if(!tree)
		return NULL;

	avl_node_t **e = avl_search_key(tree, (uintptr_t) addr);
	if(!e)
		return NULL;

	avl_node_t *n = *e;
	return n->data;
}

int vm_clone_as(struct mm_address_space *addr_space)
{
	__vm_lock(false);
	/* Create a new address space */
	if(paging_clone_as(addr_space) < 0)
	{
		__vm_unlock(false);
		return -1;
	}

	addr_space->tree = NULL;

	__vm_unlock(false);
	return 0;
}

void append_mapping(struct vm_object *vmo, struct vm_entry *region)
{
	acquire_spinlock(&vmo->mapping_lock);

	struct vm_entry **pp = &vmo->mappings;

	while(*pp)
		pp = &(*pp)->next_mapping;
	*pp = region;

	release_spinlock(&vmo->mapping_lock);
}

int vm_flush_mapping(struct vm_entry *mapping, struct process *proc)
{
	struct vm_object *vmo = mapping->vmo;
	
	assert(vmo != NULL);

	acquire_spinlock(&vmo->page_lock);

	for(struct page *p = vmo->page_list; p; p = p->next_un.next_virtual_region)
	{
		if(!__map_pages_to_vaddr(proc, (void *) (mapping->base + p->off), p->paddr,
			PAGE_SIZE, mapping->rwx))
		{
			release_spinlock(&vmo->page_lock);
			return -1;
		}
	}

	release_spinlock(&vmo->page_lock);

	return 0;
}

static bool fork_vm_region(avl_node_t *node)
{
	struct vm_entry *region = node->data;
	
	/* Do this with COW: append_mapping(region->vmo, region); */

	struct vm_object *new_object = vmo_fork(region->vmo);

	if(!new_object)
	{
		return true;
	}
	
	new_object->mappings = region;
	region->vmo = new_object;

	vm_flush_mapping(region, region->mm->process);
	return false;
}

int vm_fork_as(struct mm_address_space *addr_space)
{
	__vm_lock(false);
	if(paging_fork_tables(addr_space) < 0)
	{
		__vm_unlock(false);
		return -1;
	}

	avl_node_t *new_tree = avl_copy(*vmm_get_tree(), addr_space->process);
	if(!new_tree)
	{
		/* TODO: Do something to clean up the new page tables */
		__vm_unlock(false);
		return -1;
	}

	if(avl_traverse(new_tree, fork_vm_region) == true)
	{
		__vm_unlock(false);
		return -1;
	}
	addr_space->tree = new_tree;

	__vm_unlock(false);
	return 0;
}

void vmm_change_perms(void *range, size_t pages, int perms)
{
	bool kernel = is_higher_half(range);

	__vm_lock(kernel);
	for(size_t i = 0; i < pages; i++)
	{
		paging_change_perms(range, perms);
	}
	
	__vm_unlock(kernel);
}

void *vmalloc(size_t pages, int type, int perms)
{
	void *addr = vmm_allocate_virt_address(VM_KERNEL, pages, type, perms, 0);
	if(!addr)
		return NULL;

	vmm_map_range(addr, pages, perms);
	return addr;
}

void vfree(void *ptr, size_t pages)
{
	vmm_destroy_mappings(ptr, pages);
	vmm_unmap_range(ptr, pages);
}

avl_node_t **vmm_get_tree()
{
	struct process *p = get_current_process();
	if(!p)
		return NULL;
	return &p->address_space.tree;
}

int vmm_check_pointer(void *addr, size_t needed_space)
{
	struct vm_entry *e = vmm_is_mapped(addr);
	if(!e)
		return -1;
	if((uintptr_t) addr + needed_space <= e->base + e->pages * PAGE_SIZE)
		return 0;
	else
		return -1;
}

void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t off)
{
	file_desc_t *file_descriptor = NULL;
	if(length == 0)
		return (void*) -EINVAL;
	if(!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
		return (void*) -EINVAL;
	if(flags & MAP_PRIVATE && flags & MAP_SHARED)
		return (void*) -EINVAL;
	/* If we don't like the offset, return EINVAL */
	if(off % PAGE_SIZE)
		return (void*) -EINVAL;

	if(!(flags & MAP_ANONYMOUS)) /* This is a file-backed mapping */
	{
		if(validate_fd(fd) < 0)
			return (void*)-EBADF;
		ioctx_t *ctx = &get_current_process()->ctx;
		/* Get the file descriptor */
		file_descriptor = ctx->file_desc[fd];
		bool fd_has_write = !(file_descriptor->flags & O_WRONLY) &&
				    !(file_descriptor->flags & O_RDWR);
		if(fd_has_write && prot & PROT_WRITE
		&& flags & MAP_SHARED)
		{
			/* You can't map for writing on a file without read access with MAP_SHARED! */
			return (void*) -EACCES;
		}
	}
	void *mapping_addr = NULL;
	/* Calculate the pages needed for the overall size */
	size_t pages = length / PAGE_SIZE;
	if(length % PAGE_SIZE)
		pages++;
	int vm_prot = VM_USER |
		      ((prot & PROT_WRITE) ? VM_WRITE : 0) |
		      ((!(prot & PROT_EXEC)) ? VM_NOEXEC : 0);

	if(is_higher_half(addr)) /* User addresses can't be on the kernel's address space */
	{
		if(flags & MAP_FIXED)
			return (void *) -ENOMEM;
		addr = NULL;
	}

	if(!addr)
	{
		if(flags & MAP_FIXED)
			return (void *) -ENOMEM;
		/* Specified by POSIX, if addr == NULL, guess an address */
		mapping_addr = vmm_allocate_virt_address(VM_ADDRESS_USER, pages,
			VM_TYPE_SHARED, vm_prot, 0);
	}
	else
	{
		mapping_addr = vmm_reserve_address(addr, pages, VM_TYPE_REGULAR, vm_prot);
		if(!mapping_addr)
		{
			if(flags & MAP_FIXED)
				return (void*) -ENOMEM;
			mapping_addr = vmm_allocate_virt_address(VM_ADDRESS_USER, pages, VM_TYPE_REGULAR, vm_prot, 0);
		}
	}

	if(!mapping_addr)
		return (void*) -ENOMEM;

	if(!(flags & MAP_ANONYMOUS))
	{
		struct vm_entry *area = (*avl_search_key(vmm_get_tree(), (uintptr_t) mapping_addr))->data;
		/* Set additional meta-data */
		if(flags & MAP_SHARED)
			area->mapping_type = MAP_SHARED;
		else
			area->mapping_type = MAP_PRIVATE;

		area->type = VM_TYPE_FILE_BACKED;
		area->offset = off;
		area->fd = get_file_description(fd);
		area->fd->refcount++;

		if((file_descriptor->vfs_node->i_type == VFS_TYPE_BLOCK_DEVICE 
		|| file_descriptor->vfs_node->i_type == VFS_TYPE_CHAR_DEVICE) && area->mapping_type == MAP_SHARED)
		{
			struct inode *vnode = file_descriptor->vfs_node;
			if(!vnode->i_fops.mmap)
				return (void*) -ENOSYS;
			return vnode->i_fops.mmap(area, vnode);
		}
	}
	
	if(setup_vmregion_backing(mapping_addr, pages, !(flags & MAP_ANONYMOUS)) < 0)
			return (void *) -ENOMEM;
	return mapping_addr;
}

int sys_munmap(void *addr, size_t length)
{
	printk("munmap %p %lu\n", addr, length);
	if (is_higher_half(addr))
		return -EINVAL;
	size_t pages = length / PAGE_SIZE;
	if(length % PAGE_SIZE)
		pages++;
	
	if(!((uintptr_t) addr & 0xFFFFFFFFFFFFF000))
		return errno =-EINVAL;
	
	if(!vmm_is_mapped(addr))
		return errno =-EINVAL;
	
	vmm_unmap_range(addr, pages);
	__vm_lock(false);	
	vmm_destroy_mappings(addr, pages);
	__vm_unlock(false);

	return 0;
}

void print_vmm_structs(avl_node_t *node);
int sys_mprotect(void *addr, size_t len, int prot)
{
	printk("mprotect %p\n", addr);
	if(is_higher_half(addr))
		return -EINVAL;
	struct vm_entry *area = NULL;

	if(!(area = vmm_is_mapped(addr)))
	{
		return -EINVAL;
	}
	__vm_lock(false);
	/* The address needs to be page aligned */
	if((uintptr_t) addr % PAGE_SIZE)
	{
		__vm_unlock(false);
		return -EINVAL;
	}
	
	/* Error on len misalignment */
	if(len % PAGE_SIZE)
	{
		__vm_unlock(false);
		return -EINVAL;
	}
	
	int vm_prot = VM_USER |
		      ((prot & PROT_WRITE) ? VM_WRITE : 0) |
		      ((!(prot & PROT_EXEC)) ? VM_NOEXEC : 0);

	size_t pages = vmm_align_size_to_pages(len);

	/* TODO: Doesn't support mprotects that span multiple regions */

	len = pages * PAGE_SIZE; /* Align len on a page boundary */
	if(area->base == (uintptr_t) addr && area->pages * PAGE_SIZE == len)
	{
		area->rwx = vm_prot;
	}
	else if(area->base == (uintptr_t) addr && area->pages * PAGE_SIZE > len)
	{
		uintptr_t second_half = (uintptr_t) addr + len;
		size_t rest_pages = area->pages - pages;
		int old_rwx = area->rwx;
		avl_node_t *node = *avl_search_key(vmm_get_tree(), (uintptr_t) addr);
		node->end -= area->pages * PAGE_SIZE - len;
		area->pages = pages;
		area->rwx = vm_prot;

		struct vm_entry *new = avl_insert_key(vmm_get_tree(), second_half, rest_pages * PAGE_SIZE);
		if(!new)
			return -ENOMEM;
		
		memcpy(new, area, sizeof(struct vm_entry));
		new->base = second_half;
		new->pages = rest_pages;
		new->rwx = old_rwx;
	}
	else if(area->base < (uintptr_t) addr && area->base + area->pages * PAGE_SIZE > (uintptr_t) addr + len)
	{
		size_t total_pages = area->pages;
		avl_node_t *node = *avl_search_key(vmm_get_tree(), area->base);
		node->end -= (uintptr_t) addr - area->base;
		area->pages = ((uintptr_t) addr - area->base) / PAGE_SIZE;

		struct vm_entry *second_area = avl_insert_key(vmm_get_tree(), (uintptr_t) addr, (uintptr_t) len);
		if(!second_area)
		{
			/* TODO: Unsafe to just return, maybe restore the old area? */
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
		memcpy(second_area, area, sizeof(struct vm_entry));

		second_area->base = (uintptr_t) addr;
		second_area->pages = pages;
		second_area->type = area->type;
		second_area->rwx = vm_prot;

		struct vm_entry *third_area = avl_insert_key(vmm_get_tree(), (uintptr_t) addr + len, 
		(uintptr_t) total_pages * PAGE_SIZE);
		if(!third_area)
		{
			/* TODO: Unsafe to just return, maybe restore the old area? */
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
		memcpy(third_area, area, sizeof(struct vm_entry));
		third_area->base = (uintptr_t) addr + len;
		third_area->pages = total_pages - pages - area->pages;
		third_area->type = area->type;
		third_area->rwx = area->rwx;
	}
	else if(area->base < (uintptr_t) addr && (uintptr_t) addr + len == area->base + area->pages * PAGE_SIZE)
	{
		area->pages -= pages;
		avl_node_t *node = *avl_search_key(vmm_get_tree(), (uintptr_t) addr);
		node->end -= pages * PAGE_SIZE;
		struct vm_entry *new_area = avl_insert_key(vmm_get_tree(), (uintptr_t) addr, len);
		if(!new_area)
		{
			area->pages += pages;
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
		memcpy(new_area, area, sizeof(struct vm_entry));
		new_area->base = (uintptr_t) addr;
		new_area->pages = pages;
		new_area->type = area->type;
		new_area->rwx = vm_prot;
	}
	__vm_unlock(false);
	vmm_change_perms(addr, pages, vm_prot);

	return 0;
}

int do_inc_brk(void *oldbrk, void *newbrk)
{
	void *oldpage = page_align_up(oldbrk);
	void *newpage = page_align_up(newbrk);

	size_t pages = ((uintptr_t) newpage - (uintptr_t) oldpage) / PAGE_SIZE;
	if(vmm_map_range(oldpage, pages, VM_WRITE | VM_USER | VM_NOEXEC) == NULL)
		return -1;
	return 0;
}

uint64_t sys_brk(void *newbrk)
{
	struct process *p = get_current_process();
	if(newbrk == NULL)
		return (uint64_t) p->address_space.brk;

	void *old_brk = p->address_space.brk;
	ptrdiff_t diff = (ptrdiff_t) newbrk - (ptrdiff_t) old_brk;

	if(diff < 0)
	{
		/* TODO: Implement freeing memory with brk(2) */
		p->address_space.brk = newbrk;
	}
	else
	{
		/* Increment the program brk */
		if(do_inc_brk(old_brk, newbrk) < 0)
			return -ENOMEM;

		p->address_space.brk = newbrk;
	}
	return (uint64_t) p->address_space.brk;
}

void print_vmm_structs(avl_node_t *node)
{
	if(node->left)
		print_vmm_structs(node->left);
	printf("[Base %016lx Length %016lx End %016lx]\n", node->data->base, node->data->pages
		* PAGE_SIZE, (uintptr_t) node->data->base + node->data->pages * PAGE_SIZE);
	if(node->right)
		print_vmm_structs(node->right);
}

void vmm_print_stats(void)
{
	struct process *current = get_current_process();
	if(current)
		print_vmm_structs(current->address_space.tree);
	print_vmm_structs(kernel_tree);
}

void *__map_pages_to_vaddr(struct process *process, void *virt, void *phys,
		size_t size, size_t flags)
{
	size_t pages = vmm_align_size_to_pages(size);

	void *ptr = virt;
	for(uintptr_t virt = (uintptr_t) ptr, _phys = (uintptr_t) phys, i = 0; i < pages; virt += PAGE_SIZE, 
		_phys += PAGE_SIZE, ++i)
	{
		if(!vm_map_page(process, virt, _phys, flags))
			return NULL;
	}

	paging_invalidate(virt, pages);
	return ptr;
}

void *map_pages_to_vaddr(void *virt, void *phys, size_t size, size_t flags)
{
	return __map_pages_to_vaddr(NULL, virt, phys, size, flags);
}

void *dma_map_range(void *phys, size_t size, size_t flags)
{
	size_t pages = vmm_align_size_to_pages(size);
	void *ptr = vmm_allocate_virt_address(flags & VM_USER ? VM_ADDRESS_USER : VM_KERNEL, pages, VM_TYPE_REGULAR, flags, 0);
	if(!ptr)
		return NULL;
	/* TODO: Clean up if something goes wrong */
	return map_pages_to_vaddr(ptr, phys, size, flags);
}

int __vm_handle_pf(struct vm_entry *entry, struct fault_info *info)
{
	assert(entry->vmo != NULL);
	uintptr_t vpage = info->fault_address & -PAGE_SIZE;
	struct page *page = NULL;

	if(!(page = vmo_get(entry->vmo, vpage - entry->base, true)))
	{
		info->error = VM_SIGSEGV;
		printk("Error getting page\n");
		return -1;
	}

	//printk("Mapping %p to %lx\n", page->paddr, vpage);
	if(!map_pages_to_vaddr((void *) vpage, page->paddr, PAGE_SIZE, entry->rwx))
	{
		/* TODO: Properly destroy this */
		info->error = VM_SIGSEGV;
		return -1;
	}

	return 0;
}

int vmm_handle_page_fault(struct fault_info *info)
{
	struct vm_entry *entry = vmm_is_mapped((void*) info->fault_address);
	if(!entry)
	{
		info->error = VM_SIGSEGV;
		return -1;
	}
	if(info->write && !(entry->rwx & VM_WRITE))
		return -1;
	if(info->exec && entry->rwx & VM_NOEXEC)
		return -1;
	if(info->user && !(entry->rwx & VM_USER))
		return -1;
	return __vm_handle_pf(entry, info);
}

void vmm_destroy_addr_space(avl_node_t *tree)
{
	avl_destroy_tree(tree);
}

/* Sanitizes an address. To be used by program loaders */
int vm_sanitize_address(void *address, size_t pages)
{
	if(is_higher_half(address))
		return -1;
	if(is_invalid_arch_range(address, pages) < 0)
		return -1;
	return 0;
}

/* Generates an mmap base, should be enough for mmap */
void *vmm_gen_mmap_base(void)
{
	uintptr_t mmap_base = arch_mmap_base;
#ifdef CONFIG_ASLR
	if(enable_aslr)
	{
		mmap_base = vm_randomize_address(mmap_base, MMAP_ASLR_BITS);

		return (void*) mmap_base;
	}
#endif
	return (void*) mmap_base;
}

void *vmm_gen_brk_base(void)
{
	uintptr_t brk_base = arch_brk_base;
#ifdef CONFIG_ASLR
	if(enable_aslr)
	{
		brk_base = vm_randomize_address(arch_brk_base, BRK_ASLR_BITS);
		return (void*) brk_base;
	}
#endif
	return (void*) brk_base;
}

int sys_memstat(struct memstat *memstat)
{
	if(vmm_check_pointer(memstat, sizeof(struct memstat)) < 0)
		return -EFAULT;
	page_get_stats(memstat);
	return 0;
}

/* Reads from vm_aslr - reads enable_aslr */
ssize_t aslr_read(void *buffer, size_t size, off_t off)
{
	UNUSED(size);
	UNUSED(off);
	char *buf = buffer;
	if(enable_aslr)
	{
		*buf = '1';
	}
	else
		*buf = '0';
	return 1;
}

/* Writes to vm_aslr - modifies enable_aslr */
ssize_t aslr_write(void *buffer, size_t size, off_t off)
{
	UNUSED(size);
	UNUSED(off);
	char *buf = buffer;
	if(*buf == '1')
	{
		enable_aslr = true;
	}
	else if(*buf == '0')
	{
		enable_aslr = false;
	}
	return 1;
}

ssize_t vmm_traverse_kmaps(avl_node_t *node, char *address, size_t *size, off_t off)
{
	UNUSED(node);
	UNUSED(size);
	UNUSED(off);
	/* First write the lowest addresses, then the middle address, and then the higher addresses */
	strcpy(address, "unimplemented\n");
	return strlen(address);
}

ssize_t kmaps_read(void *buffer, size_t size, off_t off)
{
	UNUSED(off);
	return vmm_traverse_kmaps(kernel_tree, buffer, &size, 0);
}

void vmm_sysfs_init(void)
{
	INFO("vmm", "Setting up /sys/vm, /sys/vm_aslr and /sys/kmaps\n");
	struct inode *sysfs = open_vfs(get_fs_root(), "/sys");
	if(!sysfs)
		panic("vmm_sysfs_init: /sys not mounted!\n");
	struct sysfs_file *vmfile = sysfs_create_entry("vm", 0666, sysfs);
	if(!vmfile)
		panic("vmm_sysfs_init: Could not create /sys/vm\n");
	
	struct sysfs_file *aslr_control = sysfs_create_entry("vm_aslr", 0666, sysfs);
	if(!aslr_control)
		panic("vmm_sysfs_init: Could not create /sys/vm_aslr\n");
	aslr_control->read = aslr_read;
	aslr_control->write = aslr_write;

	struct sysfs_file *kmaps = sysfs_create_entry("kmaps", 0400, sysfs);
	if(!kmaps)
		panic("vmm_sysfs_init: Could not create /sys/kmaps\n");
	kmaps->read = kmaps_read;
}

int vmm_mark_cow(struct vm_entry *area)
{
	/* If the area isn't writable, don't mark it as COW */
	if(!(area->rwx & VM_WRITE))
		return errno = EINVAL, -1;
	area->flags |= VM_COW;
	return 0;
}

struct vm_entry *vmm_is_mapped_and_writable(void *usr)
{
	struct vm_entry *entry = vmm_is_mapped(usr);
	if(unlikely(!entry))	return NULL;
	if(likely(entry->rwx & VM_WRITE))	return entry;

	return NULL;
}

struct vm_entry *vmm_is_mapped_and_readable(void *usr)
{
	struct vm_entry *entry = vmm_is_mapped(usr);
	if(unlikely(!entry))	return NULL;
	return entry;
}

ssize_t copy_to_user(void *usr, const void *data, size_t len)
{
	char *usr_ptr = usr;
	const char *data_ptr = data;
	while(len)
	{
		struct vm_entry *entry;
		if((entry = vmm_is_mapped_and_writable(usr_ptr)) == NULL)
		{
			return -EFAULT;
		}
		size_t count = (entry->base + entry->pages * PAGE_SIZE) - (size_t) usr_ptr;
		if(likely(count > len)) count = len;
		memcpy(usr_ptr, data_ptr, count);
		usr_ptr += count;
		data_ptr += count;
		len -= count;
	}
	return len;
}

ssize_t copy_from_user(void *data, const void *usr, size_t len)
{
	const char *usr_ptr = usr;
	char *data_ptr = data;
	while(len)
	{
		struct vm_entry *entry;
		if((entry = vmm_is_mapped_and_readable((void*) usr_ptr)) == NULL)
		{
			return -EFAULT;
		}
		size_t count = (entry->base + entry->pages * PAGE_SIZE) - (size_t) usr_ptr;
		if(likely(count > len)) count = len;
		memcpy(data_ptr, usr_ptr, count);
		usr_ptr += count;
		data_ptr += count;
		len -= count;
	}
	return len;
}

char *strcpy_from_user(const char *usr_ptr)
{
	char *buf = zalloc(PATH_MAX + 1);
	if(!buf)
		return NULL;
	size_t used_buf = 0;
	size_t size_buf = PATH_MAX;
	
	while(true)
	{
		struct vm_entry *entry;
		if((entry = vmm_is_mapped_and_readable((void*) usr_ptr)) == NULL)
		{
			return errno = EFAULT, NULL;
		}

		size_t count = (entry->base + entry->pages * PAGE_SIZE) - (size_t) usr_ptr;
		for(size_t i = 0; i < count; i++, used_buf++)
		{
			if(used_buf == size_buf)
			{
				/* If we reach the limit of the buffer, realloc
				 *  a new one */
				char *old_buf = buf;
				size_buf += PATH_MAX;
				
				if(!(buf = realloc(buf, size_buf + 1)))
				{
					free(old_buf);
					return errno = ENOMEM, NULL;
				}
				
				memset(buf + used_buf, 0, (size_buf - used_buf) + 1);
			}

			buf[used_buf] = *usr_ptr++;
			if(buf[used_buf] == '\0')
				return buf;
		}
	}

}

void vm_update_addresses(uintptr_t new_kernel_space_base)
{
	vmalloc_space 	+= new_kernel_space_base;
	kstacks_addr 	+= new_kernel_space_base;
	heap_addr 	+= new_kernel_space_base;
	high_half 	= new_kernel_space_base;
}
uint32_t arc4random(void);

uintptr_t vm_randomize_address(uintptr_t base, uintptr_t bits)
{
	if(bits != 0)
		bits--;
	uintptr_t mask = UINTPTR_MAX & ~(-(1UL << bits));
	/* Get entropy from arc4random() */
	uintptr_t result = ((uintptr_t) arc4random() << 12) & mask;
	result |= ((uintptr_t) arc4random() << 44) & mask;

	base |= result;
	return base;
}

void vm_do_fatal_page_fault(struct fault_info *info)
{
	bool is_user_mode = info->user;

	if(is_user_mode)
	{
		struct process *current = get_current_process();
		printk("SEGV at %016lx at ip %lx in process %u(%s)\n", 
			info->fault_address, info->ip,
			current->pid, current->cmd_line);
		__asm__ __volatile__("hlt");
		kernel_raise_signal(SIGSEGV, get_current_process());
	}
	else
		panic("Unable to satisfy paging request");
}

void *get_pages(size_t flags, uint32_t type, size_t pages, size_t prot, uintptr_t alignment)
{
	void *va = vmm_allocate_virt_address(flags, pages, type, prot, alignment);
	if(!va)
		return NULL;
	if(!(flags & VM_ADDRESS_USER))
	{
		struct page *p = vmm_map_range(va, pages, prot);
		if(!p)
		{
			/* TODO: Destroy the address space region */
			return NULL;
		}
	}
	else
	{
		if(setup_vmregion_backing(va, pages, false) < 0)
			return NULL;
	}

	return va;
}

void *get_user_pages(uint32_t type, size_t pages, size_t prot)
{
	return get_pages(VM_ADDRESS_USER, type, pages, prot | VM_USER, 0);
}

struct page *vmo_commit_file(size_t off, struct vm_object *vmo)
{
	struct page *page = get_phys_page();
	if(!page)
		return NULL;

	page->off = off;
	void *ptr = PHYS_TO_VIRT(page->paddr);
	off_t eff_off = off + vmo->u_info.fmap.off;
	struct inode *file = vmo->u_info.fmap.fd->vfs_node;
	size_t to_read = file->i_size - eff_off < PAGE_SIZE ? file->i_size - eff_off : PAGE_SIZE;

	size_t read = read_vfs(0,
		    eff_off,
		    to_read,
		    ptr,
		    file);
	if(read != to_read)
	{
		printk("Error file read %lx bytes out of %lx, off %lx\n", read, to_read, eff_off);
		perror("file");
		/* TODO: clean up */
		return NULL;
	}
	//printk("Got page %p for off %lu\n", page->paddr, off);
	return page;
}

struct page *vmo_commit_shared(size_t off, struct vm_object *vmo)
{
	struct file_description *fd = vmo->u_info.fmap.fd;
	
	struct page *p = file_get_page(fd->vfs_node, off + vmo->u_info.fmap.off);
	if(!p)
		return NULL;
	p->off = off;
	atomic_inc(&p->ref, 1);
	return p;
}

int setup_vmregion_backing(void *vaddr, size_t pages, bool is_file_backed)
{
	struct vm_entry *region = vmm_is_mapped(vaddr);
	if(!region)
		return 0;

	struct vm_object *vmo;
	if(is_file_backed)
	{
		vmo = vmo_create(pages * PAGE_SIZE, NULL);
		if(!vmo)
			return -1;
		vmo->commit = (region->mapping_type == MAP_PRIVATE) ? vmo_commit_file
			 : vmo_commit_shared;
		vmo->u_info.fmap.fd = region->fd;
		vmo->u_info.fmap.off = region->offset;
		vmo->mappings = region;
	}
	else
		vmo = vmo_create_phys(pages * PAGE_SIZE);

	if(!vmo)
		return -1;
	vmo->mappings = region;

	/* Get rid of any previous vmos that might have existed */
	/* TODO: Clean up the structure and find any pages that might've been mapped */
	if(region->vmo)
		free(region->vmo);
	region->vmo = vmo;
	return 0;
}

bool is_mapping_shared(struct vm_entry *region)
{
	return region->mapping_type == MAP_SHARED;
}

bool is_file_backed(struct vm_entry *region)
{
	return region->type == VM_TYPE_FILE_BACKED;
}

void *create_file_mapping(void *addr, size_t pages, int flags,
	int prot, struct file_description *fd, off_t off)
{
	if(!addr)
	{
		if(!(addr = get_user_pages(VM_TYPE_REGULAR, pages, prot)))
		{
			return NULL;
		}
	}
	else
	{
		if(!vmm_reserve_address(addr, pages, VM_TYPE_REGULAR, prot))
		{
			if(flags & VM_MMAP_FIXED)
				return NULL;
			if(!(addr = get_user_pages(VM_TYPE_REGULAR, pages, prot)))
			{
				return NULL;
			}
		}
	}

	struct vm_entry *entry = vm_find_region(addr);
	assert(entry != NULL);

	/* TODO: Maybe we shouldn't use MMAP flags and use these new ones instead? */
	int mmap_like_type =  flags & VM_MMAP_PRIVATE ? MAP_PRIVATE : MAP_SHARED;
	entry->mapping_type = mmap_like_type;
	entry->type = VM_TYPE_FILE_BACKED;
	entry->offset = off;
	//printk("Created file mapping at %lx for off %lu\n", entry->base, off);
	entry->fd = fd;
	fd->refcount++;
	if(setup_vmregion_backing(addr, pages, true) < 0)
		return NULL;
	return addr;
}

void *map_user(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	addr = vmm_reserve_address(addr, pages, type, prot);
	if(!addr)
		return NULL;
	if(setup_vmregion_backing(addr, pages, false) < 0)
		return NULL;
	return addr;
}
