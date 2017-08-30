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

#include <kernel/file.h>
#include <kernel/paging.h>
#include <kernel/page.h>
#define __need_avl_node_t
#include <kernel/vmm.h>
#include <kernel/panic.h>
#include <kernel/compiler.h>
#include <kernel/process.h>
#include <kernel/log.h>
#include <kernel/dev.h>
#include <kernel/random.h>
#include <kernel/sysfs.h>
#include <kernel/vfs.h>

#include <kernel/vm_layout.h>

#include <drivers/rtc.h>

#include <sys/mman.h>

typedef struct avl_node
{
	struct avl_node *left, *right;
	uintptr_t key;
	uintptr_t end;
	vmm_entry_t *data;
} avl_node_t;

static spinlock_t kernel_vm_spl;
bool is_initialized = false;
bool is_spawning = 0;
static bool enable_aslr = true;
avl_node_t *old_tree = NULL;
vmm_entry_t *areas = NULL;
size_t num_areas = 3;

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
static avl_node_t *tree = NULL;

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

static vmm_entry_t *avl_insert_key(avl_node_t **t, uintptr_t key, uintptr_t end)
{
	avl_node_t *ptr = *t;
	if(!*t)
	{
		*t = malloc(sizeof(avl_node_t));
		if(!*t)
			return NULL;
		memset(*t, 0, sizeof(avl_node_t));
		ptr = *t;
		ptr->key = key;
		ptr->end = end;
		ptr->data = malloc(sizeof(vmm_entry_t));
		return ptr->data;
	}
	else if (key < ptr->key)
	{
		vmm_entry_t *ret = avl_insert_key(&ptr->left, key, end);
		if(key < high_half)
			avl_balance_tree(vmm_get_tree());
		else
			avl_balance_tree(&kernel_tree);
		return ret;
	}
	else
	{
		vmm_entry_t *ret = avl_insert_key(&ptr->right, key, end);
		if(key < high_half)
			avl_balance_tree(vmm_get_tree());
		else
			avl_balance_tree(&kernel_tree);
		return ret;
	}
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

avl_node_t *avl_copy(avl_node_t *node)
{
	avl_node_t *new = malloc(sizeof(avl_node_t));
	assert(new != NULL);
	memcpy(new, node, sizeof(avl_node_t));

	if(new->left) new->left = avl_copy(new->left);
	if(new->right) new->right = avl_copy(new->right);

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

static inline void __vm_lock(bool kernel)
{
	if(kernel)
		acquire_spinlock(&kernel_vm_spl);
	else
		acquire_spinlock((spinlock_t*) &get_current_process()->vm_spl);
}

static inline void __vm_unlock(bool kernel)
{
	if(kernel)
		release_spinlock(&kernel_vm_spl);
	else
		release_spinlock((spinlock_t*) &get_current_process()->vm_spl);
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

static int vmm_comp(const void *ptr1, const void *ptr2)
{
	const vmm_entry_t *a = (const vmm_entry_t*) ptr1;
	const vmm_entry_t *b = (const vmm_entry_t*) ptr2;

	return a->base < b->base ? -1 :
		b->base < a->base ?  1 :
		a->pages < b->pages ? -1 :
		b->pages < a->pages ?  1 :
	                            0 ;
}

void heap_set_start(uintptr_t start);

void vmm_late_init(void)
{
	uintptr_t heap_addr_no_aslr = heap_addr;

	kstacks_addr = vm_randomize_address(kstacks_addr, KSTACKS_ASLR_BITS);
	vmalloc_space = vm_randomize_address(vmalloc_space, VMALLOC_ASLR_BITS);
	heap_addr = vm_randomize_address(heap_addr, HEAP_ASLR_BITS);

	vmm_map_range((void*) heap_addr, vmm_align_size_to_pages(0x400000),
								   VM_WRITE 
								   | VM_NOEXEC
								   | VM_GLOBAL);
	heap_set_start(heap_addr);

	size_t heap_size = 0x200000000000 - (heap_addr - heap_addr_no_aslr);
	/* Start populating the address space */
	vmm_entry_t *v = avl_insert_key(&kernel_tree,
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
	v->rwx = VM_WRITE;

	is_initialized = true;
}

void *vmm_map_range(void *range, size_t pages, uint64_t flags)
{
	bool kernel = is_higher_half(range);

	__vm_lock(kernel);
	uintptr_t mem = (uintptr_t) range;
	for (size_t pgs = 0; pgs < pages; pgs++)
	{
		uintptr_t paddr = (uintptr_t) __alloc_page(PAGE_AREA_HIGH_MEM);
		if(!paddr)
			return NULL;
		if(!paging_map_phys_to_virt(mem, paddr, flags))
			panic("out of memory.");
		if(pages_are_registered())
		{
			page_increment_refcount((void*) paddr);
		}
		__asm__ __volatile__("invlpg %0"::"m"(mem));
		mem += PAGE_SIZE;
	}
	
	__vm_unlock(kernel);
	return range;
}

void vmm_unmap_range(void *range, size_t pages)
{
	bool kernel = is_higher_half(range);

	__vm_lock(kernel);
	uintptr_t mem = (uintptr_t) range;
	for (size_t i = 0; i < pages; i++)
	{
		void *page = paging_unmap((void*) mem);
		if(page)	
		{
			__free_page(page);
			page_decrement_refcount(page);
		}
		mem += 0x1000;
	}
	__vm_unlock(kernel);
}

void vmm_destroy_mappings(void *range, size_t pages)
{
#if 0
	if(!vmm_is_mapped(range))
		return;
	for(size_t i = 0; i < num_areas; i++)
	{
		if(areas[i].base == (uintptr_t)range && areas[i].pages == pages)
		{
			areas[i].base = 0xFFFFFFFFFFFFFFFF;
			areas[i].pages = 0xFFFFFFF;
			num_areas--;
			break;
		}
		if(areas[i].base + areas[i].pages * PAGE_SIZE > (uintptr_t) range && areas[i].base < (uintptr_t) range)
		{
			if((uintptr_t) (range + pages * PAGE_SIZE) != areas[i].base + areas[i].pages * PAGE_SIZE)
			{
				size_t old_pages = areas[i].pages;
				areas[i].pages -= ((uintptr_t) range - areas[i].base / 4096);
				size_t second_half_pages = old_pages - pages - areas[i].pages;
				num_areas++;
				areas = realloc(areas, sizeof(vmm_entry_t) * num_areas);
				areas[num_areas-1].base = (uintptr_t)range + pages * PAGE_SIZE;
				areas[num_areas-1].pages = second_half_pages;
				qsort(areas,num_areas,sizeof(vmm_entry_t),vmm_comp);
				if(likely(get_current_process()))
					release_spinlock((spinlock_t*) &get_current_process()->vm_spl);
				return;
			}
			else
			{
				areas[i].pages -= pages;
				if(likely(get_current_process()))
					release_spinlock((spinlock_t*) &get_current_process()->vm_spl);
				return;
			}
		}
	}
	areas = realloc(areas, sizeof(vmm_entry_t) * num_areas);
	qsort(areas,num_areas,sizeof(vmm_entry_t),vmm_comp);
	if(likely(get_current_process()))
		release_spinlock((spinlock_t*) &get_current_process()->vm_spl);
#endif
	UNUSED(range);
	UNUSED(pages);
}

void *vmm_allocate_virt_address(uint64_t flags, size_t pages, uint32_t type, uint64_t prot, uintptr_t alignment)
{
	bool allocating_kernel = true;
	if(flags & VM_ADDRESS_USER)
		allocating_kernel = false;
	if(alignment == 0)
		alignment = 1;

	__vm_lock(allocating_kernel);
	uintptr_t base_address = 0;
	switch(type)
	{
		case VM_TYPE_SHARED:
		case VM_TYPE_STACK:
		{
			if(!(flags & 1))
			{
				process_t *p = get_current_process();
				assert(p != NULL);
				if(!p->mmap_base)
					panic("mmap_base == 0");
				base_address = (uintptr_t) get_current_process()->mmap_base;
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
				if(!get_current_process()->mmap_base)
					panic("mmap_base == 0");
				base_address = (uintptr_t) get_current_process()->mmap_base;
			}
			break;
		}
	}
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
	vmm_entry_t *en;
	
	if(flags & 1)
		en = avl_insert_key(&kernel_tree, base_address, pages * PAGE_SIZE);
	else
		en = avl_insert_key(vmm_get_tree(), base_address, pages * PAGE_SIZE);
	if(!en)
	{
		base_address = 0;
		errno = ENOMEM;
		goto ret;
	}
	en->rwx = (int) prot;
	en->type = type;
	en->pages = pages;
	en->base = base_address;
	
ret:
	__vm_unlock(allocating_kernel);
	return (void*) base_address;
}

void *vmm_reserve_address(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	bool reserving_kernel = is_higher_half(addr);
	
	__vm_lock(reserving_kernel);
	if(vmm_is_mapped(addr))
	{
		__vm_unlock(reserving_kernel);
		errno = EINVAL;
		return NULL;
	}
	vmm_entry_t *v;
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

vmm_entry_t *vmm_is_mapped(void *addr)
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

PML4 *vmm_clone_as(avl_node_t **treep)
{
	__vm_lock(false);
	/* Create a new address space */
	PML4 *pt = paging_clone_as();

	*treep = NULL;
	__vm_unlock(false);
	return pt;
}

PML4 *vmm_fork_as(avl_node_t **vmmstructs)
{
	__vm_lock(false);
	PML4 *pt = paging_fork_as();
	avl_node_t *new_tree = avl_copy(*vmm_get_tree());
	*vmmstructs = new_tree;
	__vm_unlock(false);
	return pt;
}

void vmm_stop_spawning()
{
	is_spawning = 0;
	paging_stop_spawning();
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
	process_t *p = get_current_process();
	if(!p)
		return NULL;
	return &p->tree;
}

int vmm_check_pointer(void *addr, size_t needed_space)
{
	vmm_entry_t *e = vmm_is_mapped(addr);
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
		return (void*)-EINVAL;
	if(!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
		return (void*)-EINVAL;
	if(flags & MAP_PRIVATE && flags & MAP_SHARED)
		return (void*)-EINVAL;
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
		if((file_descriptor->flags != O_WRONLY && file_descriptor->flags != O_RDWR) && prot & PROT_WRITE
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
		addr = NULL;

	if(!addr) /* Specified by POSIX, if addr == NULL, guess an address */
		mapping_addr = vmm_allocate_virt_address(VM_ADDRESS_USER, pages, VM_TYPE_SHARED, vm_prot, 0);
	else
	{
		mapping_addr = vmm_reserve_address(addr, pages, VM_TYPE_REGULAR, vm_prot);
		if(!mapping_addr)
			mapping_addr = vmm_allocate_virt_address(VM_ADDRESS_USER, pages, VM_TYPE_REGULAR, vm_prot, 0);
	}
	if(!mapping_addr)
		return (void*)-ENOMEM;

	if(!(flags & MAP_ANONYMOUS))
	{
		vmm_entry_t *area = (*avl_search_key(vmm_get_tree(), (uintptr_t) mapping_addr))->data;
		/* Set additional meta-data */
		if(flags & MAP_SHARED)
			area->mapping_type = MAP_SHARED;
		else
			area->mapping_type = MAP_PRIVATE;

		area->type = VM_TYPE_FILE_BACKED;
		area->offset = off;
		area->fd = get_file_description(fd);
		area->fd->refcount++;
		if((file_descriptor->vfs_node->type == VFS_TYPE_BLOCK_DEVICE 
		|| file_descriptor->vfs_node->type == VFS_TYPE_CHAR_DEVICE) && area->mapping_type == MAP_SHARED)
		{
			struct minor_device *m = dev_find(file_descriptor->vfs_node->dev);
			if(!m)
				return (void*) -ENODEV;
			if(!m->fops)
				return (void*) -ENOSYS;
			if(!m->fops->mmap)
				return (void*) -ENOSYS;
			return m->fops->mmap(area, file_descriptor->vfs_node);
		}
	}

	return mapping_addr;
}

int sys_munmap(void *addr, size_t length)
{
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
	vmm_destroy_mappings(addr, pages);
	return 0;
}

void print_vmm_structs(avl_node_t *node);
int sys_mprotect(void *addr, size_t len, int prot)
{
	if(is_higher_half(addr))
		return -EINVAL;
	vmm_entry_t *area = NULL;

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

		vmm_entry_t *new = avl_insert_key(vmm_get_tree(), second_half, rest_pages * PAGE_SIZE);
		if(!new)
			return -ENOMEM;
		new->base = second_half;
		new->pages = rest_pages;
		new->rwx = old_rwx;
		new->type = area->type;
	}
	else if(area->base < (uintptr_t) addr && area->base + area->pages * PAGE_SIZE > (uintptr_t) addr + len)
	{
		size_t total_pages = area->pages;
		avl_node_t *node = *avl_search_key(vmm_get_tree(), area->base);
		node->end -= (uintptr_t) addr - area->base;
		area->pages = ((uintptr_t) addr - area->base) / PAGE_SIZE;

		vmm_entry_t *second_area = avl_insert_key(vmm_get_tree(), (uintptr_t) addr, (uintptr_t) len);
		if(!second_area)
		{
			/* TODO: Unsafe to just return, maybe restore the old area? */
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
		second_area->base = (uintptr_t) addr;
		second_area->pages = pages;
		second_area->type = area->type;
		second_area->rwx = vm_prot;

		vmm_entry_t *third_area = avl_insert_key(vmm_get_tree(), (uintptr_t) addr + len, 
		(uintptr_t) total_pages * PAGE_SIZE);
		if(!third_area)
		{
			/* TODO: Unsafe to just return, maybe restore the old area? */
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
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
		vmm_entry_t *new_area = avl_insert_key(vmm_get_tree(), (uintptr_t) addr, len);
		if(!new_area)
		{
			area->pages += pages;
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
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
	process_t *p = get_current_process();
	if(newbrk == NULL)
		return (uint64_t) p->brk;

	void *old_brk = p->brk;
	ptrdiff_t diff = (ptrdiff_t) newbrk - (ptrdiff_t) old_brk;

	if(diff < 0)
	{
		/* TODO: Implement freeing memory with brk(2) */
		p->brk = newbrk;
	}
	else
	{
		/* Increment the program brk */
		if(do_inc_brk(old_brk, newbrk) < 0)
			return -ENOMEM;

		p->brk = newbrk;
	}
	return 0;
}

void print_vmm_structs(avl_node_t *node)
{
	printk("[Base %x Length %x End %x]\n", node->data->base, node->data->pages * PAGE_SIZE, 
	(uintptr_t) node->data->base + node->data->pages * PAGE_SIZE);
	if(node->left)
		print_vmm_structs(node->left);
	if(node->right)
		print_vmm_structs(node->right);
}

void vmm_print_stats(void)
{
	print_vmm_structs(tree);
}

void *dma_map_range(void *phys, size_t size, size_t flags)
{
	size_t pages = vmm_align_size_to_pages(size);

	void *ptr = vmm_allocate_virt_address(flags & VM_USER ? VM_ADDRESS_USER : VM_KERNEL, pages, VM_TYPE_REGULAR, flags, 0);
	if(!ptr)
		return NULL;
	for(uintptr_t virt = (uintptr_t) ptr, _phys = (uintptr_t) phys, i = 0; i < pages; virt += PAGE_SIZE, 
		_phys += PAGE_SIZE, ++i)
	{
		if(!paging_map_phys_to_virt(virt, _phys, flags))
			return NULL;
	}
	return ptr;
}

int __vm_handle_private(vmm_entry_t *entry, struct fault_info *info)
{
	/* Map a page */
	uintptr_t aligned_address = (info->fault_address & 0xFFFFFFFFFFFFF000);
	/* Map it as VM_WRITE so we can copy the data in */
	void *ptr = vmm_map_range((void*) aligned_address, 1, entry->rwx | VM_WRITE);
	if(!ptr)
		return -1;
	vfsnode_t *file = entry->fd->vfs_node;
	size_t to_read = file->size - entry->offset < PAGE_SIZE ? file->size - entry->offset : PAGE_SIZE;
	
	if(read_vfs(0,
		    entry->offset + (aligned_address - entry->base),
		    to_read,
		    ptr,
		    file) != to_read)
	{
		vmm_unmap_range(ptr, 1);
		return -1;
	}
	
	vmm_change_perms((void*) aligned_address, 1, entry->rwx);
	return 0;
}

int __vm_handle_shared(vmm_entry_t *entry, struct fault_info *info)
{
	return -1;
}

int __vm_handle_anon(vmm_entry_t *entry, struct fault_info *info)
{
	if(!vmm_map_range((void*)(info->fault_address & 0xFFFFFFFFFFFFF000), 1, entry->rwx))
		return -1;
	return 0;
}

int vmm_handle_page_fault(vmm_entry_t *entry, struct fault_info *info)
{
	if(info->write && !(entry->rwx & VM_WRITE))
		return -1;
	if(info->exec && entry->rwx & VM_NOEXEC)
		return -1;
	if(info->user && !(entry->rwx & VM_USER))
		return -1;
	if(entry->mapping_type == MAP_PRIVATE && entry->type == VM_TYPE_FILE_BACKED)
		return __vm_handle_private(entry, info);
	else if(entry->mapping_type == MAP_SHARED && entry->type == VM_TYPE_FILE_BACKED)
		return __vm_handle_shared(entry, info);
	else 
		return __vm_handle_anon(entry, info);
}

void vmm_destroy_addr_space(avl_node_t *tree)
{
	avl_destroy_tree(tree);
}

/* Sanitizes an address. To be used by program loaders */
int vm_sanitize_address(void *address, size_t pages)
{
	if(vmm_is_mapped(address))
		return -1;
	if(vmm_check_pointer(address, pages * PAGE_SIZE) == 0)
		return -1;
	if(is_higher_half(address))
		return -1;
	if(is_invalid_arch_range(address, pages) < 0)
		return -1;
	return 0;
}

/* Generates an mmap base, should be enough for mmap */
void *vmm_gen_mmap_base()
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
	vfsnode_t *sysfs = open_vfs(fs_root, "/sys");
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

int vmm_mark_cow(vmm_entry_t *area)
{
	/* If the area isn't writable, don't mark it as COW */
	if(!(area->rwx & VM_WRITE))
		return errno = EINVAL, -1;
	area->flags |= VM_COW;
	return 0;
}

vmm_entry_t *vmm_is_mapped_and_writable(void *usr)
{
	vmm_entry_t *entry = vmm_is_mapped(usr);
	if(unlikely(!entry))	return NULL;
	if(likely(entry->rwx & VM_WRITE))	return entry;
	return NULL;
}

ssize_t copy_to_user(void *usr, const void *data, size_t len)
{
	char *usr_ptr = usr;
	const char *data_ptr = data;
	while(len)
	{
		vmm_entry_t *entry;
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
		vmm_entry_t *entry;
		if((entry = vmm_is_mapped_and_writable((void*) usr_ptr)) == NULL)
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
