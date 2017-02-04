/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#include <kernel/paging.h>
#define __need_avl_node_t
#include <kernel/vmm.h>
#include <kernel/panic.h>
#include <kernel/compiler.h>
#include <kernel/process.h>
#include <kernel/log.h>

#include <sys/mman.h>

_Bool is_initialized = false;
_Bool is_spawning = 0;
avl_node_t *old_tree = NULL;
vmm_entry_t *areas = NULL;
size_t num_areas = 3;
#ifdef __x86_64__
const uintptr_t high_half = 0xffffc90000000000;
const uintptr_t low_half_max = 0x00007fffffffffff;
const uintptr_t low_half_min = 0x400000;
#endif
uintptr_t kstacks_offset = 0xffffff0000000000;
uintptr_t vmalloc_space = 0xffffc90000000000;
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
vmm_entry_t *avl_insert_key(avl_node_t **t, uintptr_t key, uintptr_t end)
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
			avl_balance_tree(&tree);
		else
			avl_balance_tree(&kernel_tree);
		return ret;
	}
	else
	{
		vmm_entry_t *ret = avl_insert_key(&ptr->right, key, end);
		if(key < high_half)
			avl_balance_tree(&tree);
		else
			avl_balance_tree(&kernel_tree);
		return ret;
	}
}
avl_node_t **avl_search_key(avl_node_t **t, uintptr_t key)
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
int avl_delete_node(uintptr_t key)
{
	/* Try to find the node inside the tree */
	avl_node_t **n = avl_search_key(&tree, key);
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
	if(node->left) node->left = avl_copy(node->left);
	if(node->right) node->right = avl_copy(node->right);

	avl_node_t *new = malloc(sizeof(avl_node_t));
	memcpy(new, node, sizeof(avl_node_t));
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
void vmm_init()
{
	paging_init();
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
void vmm_start_address_bookkeeping(uintptr_t framebuffer_address, uintptr_t heap)
{
	/* Start populating the address space */
	vmm_entry_t *v = avl_insert_key(&kernel_tree, framebuffer_address, framebuffer_address + 0x400000);
	
	v->base = framebuffer_address;
	/* TODO: Support multiple sizes of framebuffers */
	v->pages = 0x800000 / PAGE_SIZE;
	v->type = VM_TYPE_HW;
	v->rwx = VM_NOEXEC | VM_WRITE;
	/* TODO: Support multiple sizes of heap */
	v = avl_insert_key(&kernel_tree, heap, heap + 0x400000);

	v->base = framebuffer_address;

	v->pages = 0x400000 / PAGE_SIZE;
	v->type = VM_TYPE_HW;
	v->rwx = VM_NOEXEC | VM_WRITE;

	v = avl_insert_key(&kernel_tree, KERNEL_VIRTUAL_BASE, UINT64_MAX);

	v->base = KERNEL_VIRTUAL_BASE;
	v->pages = 0x80000000 / PAGE_SIZE;
	v->type = VM_TYPE_SHARED;
	v->rwx = VM_WRITE;

	kstacks_offset |= (rand() & 0xFFFFFFF000);
	vmalloc_space |= (rand() & 0xFFFFFFF000);

	is_initialized = true;
}
void *vmm_map_range(void *range, size_t pages, uint64_t flags)
{
	if(likely(current_process))
		acquire_spinlock(&current_process->vm_spl);
	uintptr_t mem = (uintptr_t) range;
	for (size_t pgs = 0; pgs < pages; pgs++)
	{
		paging_map_phys_to_virt(mem, (uintptr_t) bootmem_alloc(1), flags);
		asm volatile("invlpg %0"::"m"(mem));
		mem += 0x1000;
	}
	memset(range, 0, PAGE_SIZE * pages);
	if(likely(current_process))
		release_spinlock(&current_process->vm_spl);
	return range;
}
void vmm_unmap_range(void *range, size_t pages)
{
	if(likely(current_process))
		acquire_spinlock(&current_process->vm_spl);
	uintptr_t mem = (uintptr_t) range;
	for (size_t i = 0; i < pages; i++)
	{
		paging_unmap((void*) mem);
		asm volatile("invlpg %0"::"m"(mem));
		mem += 0x1000;
	}
	if(likely(current_process))
		release_spinlock(&current_process->vm_spl);
}
void vmm_destroy_mappings(void *range, size_t pages)
{
	if(!vmm_is_mapped(range))
		return;
	if(likely(current_process))
		acquire_spinlock(&current_process->vm_spl);
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
				if(likely(current_process))
					release_spinlock(&current_process->vm_spl);
				return;
			}
			else
			{
				areas[i].pages -= pages;
				if(likely(current_process))
					release_spinlock(&current_process->vm_spl);
				return;
			}
		}
	}
	areas = realloc(areas, sizeof(vmm_entry_t) * num_areas);
	qsort(areas,num_areas,sizeof(vmm_entry_t),vmm_comp);
	if(likely(current_process))
		release_spinlock(&current_process->vm_spl);
}
void *vmm_allocate_virt_address(uint64_t flags, size_t pages, uint32_t type, uint64_t prot)
{
	if(likely(current_process))
		acquire_spinlock(&current_process->vm_spl);
	uintptr_t base_address = 0;
	switch(type)
	{
		case VM_TYPE_SHARED:
		case VM_TYPE_STACK:
		{
			if(!(flags & 1))
				base_address = 0x00007a0000000000;
			else
				base_address = kstacks_offset;
			break;
		}
		default:
		case VM_TYPE_REGULAR:
		{
			if(flags & 1)
				base_address = vmalloc_space;
			else
				base_address = low_half_min;
			break;
		}
	}
	if(flags & 1)
	{
		avl_node_t **e = avl_search_key(&kernel_tree, base_address);
		while(e && *e)
		{
			avl_node_t *n = *e;
			base_address += n->data->pages * PAGE_SIZE;
			e = avl_search_key(&kernel_tree, base_address);
			if(avl_search_key(&kernel_tree, base_address + pages * PAGE_SIZE) == NULL && !e)
				break;
		}
	}
	else
	{
		avl_node_t **e = avl_search_key(&tree, base_address);
		while(e && *e)
		{
			avl_node_t *n = *e;
			base_address += n->data->pages * PAGE_SIZE;
			e = avl_search_key(&tree, base_address);
			if(avl_search_key(&tree, base_address + pages * PAGE_SIZE) == NULL && !e)
				break;
		}
	}
	vmm_entry_t *en;
	
	if(flags & 1)
		en = avl_insert_key(&kernel_tree, base_address, pages * PAGE_SIZE);
	else
		en = avl_insert_key(&tree, base_address, pages * PAGE_SIZE);

	en->rwx = (int) prot;
	en->type = type;
	en->pages = pages;
	en->base = base_address;
	if(likely(current_process))
		release_spinlock(&current_process->vm_spl);
	return (void*)base_address;
}
void *vmm_reserve_address(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	if(likely(current_process))
		acquire_spinlock(&current_process->vm_spl);
	if(vmm_is_mapped(addr))
	{
		if(likely(current_process))
			release_spinlock(&current_process->vm_spl);
		return NULL;
	}
	vmm_entry_t *v;
	if((uintptr_t) addr >= high_half)
		v = avl_insert_key(&kernel_tree, (uintptr_t)addr, pages * PAGE_SIZE);
	else
		v = avl_insert_key(&tree, (uintptr_t)addr, pages * PAGE_SIZE);
	if(!v)
	{
		addr = NULL;
		errno = ENOMEM;
		goto return_;
	}
	v->pages = pages;
	v->type = type;
	v->rwx = prot;
return_:
	if(likely(current_process))
		release_spinlock(&current_process->vm_spl);
	return addr;
}
vmm_entry_t *vmm_is_mapped(void *addr)
{
	avl_node_t **e = avl_search_key(&tree, (uintptr_t) addr);
	if(!e)
	{
		e = avl_search_key(&kernel_tree, (uintptr_t) addr);
		if(!e)
			return NULL;
	}
	avl_node_t *n = *e;
	return n->data;
}
PML4 *vmm_clone_as(avl_node_t **treep)
{
	/* Create a new address space */
	PML4 *pt = paging_clone_as();

	*treep = NULL;

	return pt;
}
PML4 *vmm_fork_as(avl_node_t **vmmstructs)
{
	PML4 *pt = paging_fork_as();
	avl_node_t *new_tree = avl_copy(tree);
	*vmmstructs = new_tree;
	return pt;
}
void vmm_stop_spawning()
{
	is_spawning = 0;
	vmm_set_tree(old_tree);
	paging_stop_spawning();
}
void vmm_change_perms(void *range, size_t pages, int perms)
{
	if(likely(current_process))
		acquire_spinlock(&current_process->vm_spl);
	for(size_t i = 0; i < pages; i++)
	{
		paging_change_perms(range, perms);
	}
	if(likely(current_process))
		release_spinlock(&current_process->vm_spl);
}
void *vmalloc(size_t pages, int type, int perms)
{
	void *addr = vmm_allocate_virt_address(VM_KERNEL, pages, type, perms);
	vmm_map_range(addr, pages, perms);
	return addr;
}
avl_node_t *vmm_get_tree()
{
	return tree;
}
void vmm_set_tree(avl_node_t *tree_)
{
	tree = tree_;
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
void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *mapping_addr = NULL;
	// Calculate the pages needed for the overall size
	size_t pages = length / PAGE_SIZE;
	if(length % PAGE_SIZE)
		pages++;
	
	int vm_prot = 0;
	vm_prot |= VMM_USER;
	if(prot & PROT_WRITE)
		vm_prot |= VMM_WRITE;
	if(!(prot & PROT_EXEC))
		vm_prot |= VMM_NOEXEC;
	if(!addr) // Specified by posix, if addr == NULL, guess an address
		mapping_addr = vmm_allocate_virt_address(0, pages, VMM_TYPE_REGULAR, vm_prot);
	else
	{
		mapping_addr = vmm_reserve_address(addr, pages, VMM_TYPE_REGULAR, vm_prot);
		if(!mapping_addr)
			mapping_addr = vmm_allocate_virt_address(0, pages, VMM_TYPE_REGULAR, vm_prot);
	}
	if(!mapping_addr)
		return errno =-ENOMEM, NULL;
	if(!vmm_map_range(mapping_addr, pages, vm_prot))
		return errno =-ENOMEM, NULL;
	return mapping_addr;
}
int sys_munmap(void *addr, size_t length)
{
	if ((uintptr_t) addr >= VM_HIGHER_HALF)
		return errno =-EINVAL;
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
int sys_mprotect(void *addr, size_t len, int prot)
{
	if(!vmm_is_mapped(addr))
		return errno =-EINVAL;
	int vm_prot = 0;
	if(prot & PROT_WRITE)
		vm_prot |= VMM_WRITE;
	if(!(prot & PROT_EXEC))
		vm_prot |= VMM_NOEXEC;
	size_t pages = len / PAGE_SIZE;
	if(len % PAGE_SIZE)
		pages++;
	vmm_change_perms(addr, pages, vm_prot);
	return 0;
}
uint64_t sys_brk(void *addr)
{
	if(addr == NULL)
		return (uint64_t) current_process->brk;
	else
		current_process->brk = addr;
	return 0;
}
