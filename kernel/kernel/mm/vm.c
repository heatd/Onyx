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
#include <onyx/vm.h>
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
#include <onyx/cpu.h>
#include <libdict/dict.h>

#include <onyx/mm/vm_object.h>

#include <onyx/vm_layout.h>

#include <sys/mman.h>

static struct spinlock kernel_vm_spl;
bool is_initialized = false;
static bool enable_aslr = false;

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
size_t heap_size = 0;

int setup_vmregion_backing(struct vm_region *region, size_t pages, bool is_file_backed);
int populate_shared_mapping(void *page, struct file_description *fd,
	struct vm_region *entry, size_t nr_pages);

int imax(int x, int y)
{
	return x > y ? x : y;
}

uintptr_t max(uintptr_t x, uintptr_t y)
{
	return x > y ? x : y;
}

#define KADDR_SPACE_SIZE	0x800000000000
#define KADDR_START		0xffff800000000000

struct mm_address_space kernel_address_space = {};

int vm_cmp(const void* k1, const void* k2)
{
	if(k1 == k2)
		return 0;

        return (unsigned long) k1 < (unsigned long) k2 ? -1 : 1; 
}

struct vm_region *vm_reserve_region(struct mm_address_space *as,
				    unsigned long start, size_t size)
{
	struct vm_region *region = (struct vm_region *) zalloc(sizeof(*region));
	if(!region)
		return NULL;

	region->base = start;
	region->pages = vm_align_size_to_pages(size);
	region->rwx = 0;

	dict_insert_result res = rb_tree_insert(as->area_tree,
						(void *) start);

	if(res.inserted == false)
	{
		free(region);
		return NULL;
	}

	if(as != &kernel_address_space)
		region->mm = &get_current_process()->address_space;

	*res.datum_ptr = region;

	return region; 
}
#define DEBUG_VM_3 0
struct vm_region *vm_allocate_region(struct mm_address_space *as,
				     unsigned long min, size_t size)
{
	if(min < as->start)
		min = as->start;

	rb_itor *it = rb_itor_new(as->area_tree);
	bool node_valid;
	unsigned long last_end = min;
	struct vm_region *f = NULL;

	if(min != as->start)
		node_valid = rb_itor_search_ge(it, (const void *) min);
	else
	{
		node_valid = rb_itor_first(it);
	}

	if(!node_valid)
		goto done;
	

	/* Check if there's a gap between the first node
	 * and the start of the address space
	*/

	f = (struct vm_region *) *rb_itor_datum(it);

#if DEBUG_VM_1
	printk("Tiniest node: %016lx\n", f->base);
#endif
	if(f->base - min >= size)
	{
#if DEBUG_VM_2
		printk("gap [%016lx - %016lx]\n", min, f->base);
#endif
		goto done;
	}
	
	while(node_valid)
	{
		struct vm_region *f = (struct vm_region *) *rb_itor_datum(it);
		last_end = f->base + (f->pages << PAGE_SHIFT);
 
		node_valid = rb_itor_next(it);
		if(!node_valid)
			break;

		struct vm_region *vm = (struct vm_region *) *rb_itor_datum(it);

		if(vm->base - last_end >= size && min <= vm->base)
			break;
	}

done:
	rb_itor_free(it);

	last_end = last_end < min ? min : last_end;

#if DEBUG_VM_3
	printk("Ptr: %lx\nSize: %lx\n", last_end, size);
#endif
	return vm_reserve_region(as, last_end, size);
}

void vm_addr_init(void)
{
	kernel_address_space.area_tree = rb_tree_new(vm_cmp);
	kernel_address_space.start = KADDR_START;
	kernel_address_space.end = UINTPTR_MAX;
	kernel_address_space.cr3 = get_current_pml4();

	assert(kernel_address_space.area_tree != NULL);
}

static inline void __vm_lock(bool kernel)
{
	if(kernel)
		spin_lock(&kernel_vm_spl);
	else
		spin_lock(&get_current_process()->address_space.vm_spl);
}

static inline void __vm_unlock(bool kernel)
{
	if(kernel)
		spin_unlock(&kernel_vm_spl);
	else
		spin_unlock(&get_current_process()->address_space.vm_spl);
}

static inline bool is_higher_half(void *address)
{
	return (uintptr_t) address > VM_HIGHER_HALF;
}

void vm_init()
{
	paging_init();
	arch_vm_init();
}

void heap_set_start(uintptr_t start);

void vm_late_init(void)
{
	/* TODO: This should be arch specific stuff, move this to arch/ */
	uintptr_t heap_addr_no_aslr = heap_addr;

	kstacks_addr = vm_randomize_address(kstacks_addr, KSTACKS_ASLR_BITS);
	vmalloc_space = vm_randomize_address(vmalloc_space, VMALLOC_ASLR_BITS);
	heap_addr = vm_randomize_address(heap_addr, HEAP_ASLR_BITS);

	vm_map_range((void*) heap_addr, vm_align_size_to_pages(0x400000),
			VM_WRITE | VM_NOEXEC);
	heap_set_start(heap_addr);

	vm_addr_init();

	heap_size = 0x200000000000 - (heap_addr - heap_addr_no_aslr);
	/* Start populating the address space */
	struct vm_region *v = vm_reserve_region(&kernel_address_space, heap_addr, heap_size);
	if(!v)
	{
		panic("vmm: early boot oom");	
	}
	v->base = heap_addr;

	v->pages = heap_size / PAGE_SIZE;
	v->type = VM_TYPE_HEAP;
	v->rwx = VM_NOEXEC | VM_WRITE;

	v = vm_reserve_region(&kernel_address_space, KERNEL_VIRTUAL_BASE, UINT64_MAX - KERNEL_VIRTUAL_BASE);
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

struct page *vm_map_range(void *range, size_t nr_pages, uint64_t flags)
{
	bool kernel = is_higher_half(range);

	__vm_lock(kernel);

	uintptr_t mem = (uintptr_t) range;
	struct page *pages = alloc_pages(nr_pages, 0);
	struct page *p = pages;
	if(!pages)
		goto out_of_mem;

#ifdef DEBUG_PRINT_MAPPING
	printk("vm_map_range: %p - %lx\n", range, (unsigned long) range + nr_pages << PAGE_SHIFT);
#endif

	for(size_t i = 0; i < nr_pages; i++)
	{
		if(!vm_map_page(NULL, mem + (i << PAGE_SHIFT), (uintptr_t) p->paddr, flags))
			goto out_of_mem;
		p = p->next_un.next_allocation;
	}

	paging_invalidate(range, nr_pages);
	__vm_unlock(kernel);

	return pages;

out_of_mem:
	if(pages)	free_pages(pages);
	__vm_unlock(kernel);
	return NULL;
}

void do_vm_unmap(void *range, size_t pages)
{
	struct vm_region *entry = vm_find_region(range);
	assert(entry != NULL);
	uintptr_t mem = (uintptr_t) range;

	struct vm_object *vmo = entry->vmo;
	assert(vmo != NULL);

	spin_lock(&vmo->page_lock);

	for(struct page *p = vmo->page_list; p != NULL;
		p = p->next_un.next_virtual_region)
	{

		paging_unmap((void *) (mem + p->off));
	}

	spin_unlock(&vmo->page_lock);
}

void vm_unmap_range(void *range, size_t pages)
{
	bool kernel = is_higher_half(range);

	__vm_lock(kernel);

	do_vm_unmap(range, pages);
	__vm_unlock(kernel);
}

void vm_region_destroy(struct vm_region *region)
{
	/* First, unref things */
	if(region->fd)	fd_unref(region->fd);

	if(region->vmo)	vmo_unref(region->vmo);

	free(region);
}

void vm_destroy_mappings(void *range, size_t pages)
{
	struct mm_address_space *mm = is_higher_half(range)
				? &kernel_address_space : &get_current_process()->address_space;
	struct vm_region *reg = vm_find_region(range);

	vm_unmap_range(range, pages);

	rb_tree_remove(mm->area_tree, (unsigned long) reg->base);
	
	vm_region_destroy(reg);
}

unsigned long vm_get_base_address(uint64_t flags, uint32_t type)
{
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
	
	return base_address;
}

struct vm_region *vm_allocate_virt_region(uint64_t flags, size_t pages, uint32_t type,
	uint64_t prot)
{
	if(pages == 0)
		return NULL;

	/* Lock everything before allocating anything */
	bool allocating_kernel = true;
	if(flags & VM_ADDRESS_USER)
		allocating_kernel = false;

	__vm_lock(allocating_kernel);

	struct mm_address_space *as = allocating_kernel ? &kernel_address_space :
		&get_current_process()->address_space;
	unsigned long base_addr = vm_get_base_address(flags, type);

	struct vm_region *region = vm_allocate_region(as, base_addr, pages << PAGE_SHIFT);

	/* Unlock and return */
	__vm_unlock(allocating_kernel);
	
	if(region)
	{
		region->rwx = prot;
		region->type = type;
	}

	return region;
}

struct vm_region *vm_reserve_address(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	bool reserving_kernel = is_higher_half(addr);
	struct vm_region *v = NULL;

	__vm_lock(reserving_kernel);
	/* BUG!: There's a bug right here, 
	 * vm_find_region() is most likely not enough 
	*/
	if(vm_find_region(addr))
	{
		__vm_unlock(reserving_kernel);
		errno = EINVAL;
		return NULL;
	}

	struct mm_address_space *mm = &get_current_process()->address_space;

	if((uintptr_t) addr >= high_half)
		v = vm_reserve_region(&kernel_address_space, (uintptr_t) addr, pages * PAGE_SIZE);
	else
		v = vm_reserve_region(mm, (uintptr_t) addr, pages * PAGE_SIZE);
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
	return v;
}

struct vm_region *vm_find_region_in_tree(void *addr, rb_tree *tree)
{
	rb_itor *it = rb_itor_new(tree);

	if(!rb_itor_search_le(it, addr))
		return NULL;
	
	while(true)
	{
		struct vm_region *region = *rb_itor_datum(it);
		if(region->base <= (unsigned long) addr
			&& region->base + (region->pages << PAGE_SHIFT) > (unsigned long) addr)
		{
			rb_itor_free(it);
			return region;
		}

		if(!rb_itor_next(it))
		{
			break;
		}
	}

	rb_itor_free(it);
	return NULL;
}

struct vm_region *vm_find_region(void *addr)
{	
	struct process *current = get_current_process();
	struct vm_region *reg = NULL;
	if(current)
	{
		reg = vm_find_region_in_tree(addr, current->address_space.area_tree);	
		if(reg)	return reg;
	}
	
	return vm_find_region_in_tree(addr, kernel_address_space.area_tree);
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

	__vm_unlock(false);
	return 0;
}

void append_mapping(struct vm_object *vmo, struct vm_region *region)
{
	spin_lock(&vmo->mapping_lock);

	struct vm_region **pp = &vmo->mappings;

	while(*pp)
		pp = &(*pp)->next_mapping;
	*pp = region;

	spin_unlock(&vmo->mapping_lock);
}

int vm_flush_mapping(struct vm_region *mapping, struct process *proc)
{
	struct vm_object *vmo = mapping->vmo;
	
	assert(vmo != NULL);

	spin_lock(&vmo->page_lock);

	for(struct page *p = vmo->page_list; p; p = p->next_un.next_virtual_region)
	{
		if(!__map_pages_to_vaddr(proc, (void *) (mapping->base + p->off), p->paddr,
			PAGE_SIZE, mapping->rwx))
		{
			spin_unlock(&vmo->page_lock);
			return -1;
		}
	}

	spin_unlock(&vmo->page_lock);

	return 0;
}

int vm_flush(struct vm_region *entry)
{
	struct process *p = entry->mm ? entry->mm->process : NULL;
#if DEBUG_VM_FLUSH
printk("Has process? %s\n", p ? "true" : "false");
#endif
	return vm_flush_mapping(entry, p);
}

struct fork_iteration
{
	struct mm_address_space *target_mm;
	bool success;
};

static bool fork_vm_region(const void *key, void *datum, void *user_data)
{
	struct fork_iteration *it = user_data;
	struct vm_region *region = datum;
	
	struct vm_region *new_region = memdup(region, sizeof(*region));
	if(!new_region)
	{
		goto ohno;
	}

#if DEBUG_FORK_VM
	printk("Forking %p, size %lx\n", key, region->pages << PAGE_SHIFT);
#endif
	/* Do this with COW: append_mapping(region->vmo, region); */
	dict_insert_result res = rb_tree_insert(it->target_mm->area_tree, key);

	if(!res.inserted)
	{
		free(new_region);
		goto ohno;
	}

	*res.datum_ptr = new_region;
	struct vm_object *new_object = vmo_fork(new_region->vmo);

	if(!new_object)
	{
		dict_remove_result res = rb_tree_remove(it->target_mm->area_tree, key);
		free(new_region);
		goto ohno;
	}
	
	new_object->mappings = new_region;
	new_region->vmo = new_object;
	new_region->mm = it->target_mm;

	if(vm_flush(new_region) < 0)
	{
		/* Let the generic addr space destruction code handle this, 
		 * since there's everything's set now */
		goto ohno;
	}

	return true;

ohno:
	it->success = false;
	return false;
}

void addr_space_delete(void *key, void *value)
{
	struct vm_region *region = value;

	do_vm_unmap((void *) region->base, region->pages);

	vm_region_destroy(region);
}

void tear_down_addr_space(struct mm_address_space *addr_space)
{
	/*
	 * Note: We free the tree first in order to free any forked pages.
	 * If we didn't we would leak some memory.
	*/
	rb_tree_free(addr_space->area_tree, addr_space_delete);

	paging_free_page_tables(addr_space);
}

int vm_fork_as(struct mm_address_space *addr_space)
{
	struct fork_iteration it = {};
	it.target_mm = addr_space;
	it.success = true;

	__vm_lock(false);
	if(paging_fork_tables(addr_space) < 0)
	{
		__vm_unlock(false);
		return -1;
	}

	struct process *current = get_current_process();

	addr_space->area_tree = rb_tree_new(vm_cmp);

	if(!addr_space->area_tree)
	{
		tear_down_addr_space(addr_space);
		__vm_unlock(false);
		return -1;
	}

	rb_tree_traverse(current->address_space.area_tree, fork_vm_region, (void *) &it);

	if(!it.success)
	{
		tear_down_addr_space(addr_space);
		__vm_unlock(false);
		return -1;
	}

	__vm_unlock(false);
	return 0;
}

void vm_change_perms(void *range, size_t pages, int perms)
{
	bool kernel = is_higher_half(range);

	__vm_lock(kernel);
	for(size_t i = 0; i < pages; i++)
	{
		paging_change_perms(range, perms);
	}
	
	__vm_unlock(kernel);
}

void *stack_trace(void);

void *vmalloc(size_t pages, int type, int perms)
{
	//stack_trace();
	struct vm_region *vm =
		vm_allocate_virt_region(VM_KERNEL, pages, type, perms);
	if(!vm)
		return NULL;

	vm->caller = (uintptr_t) __builtin_return_address(0);
	struct vm_object *vmo = vmo_create_phys(pages << PAGE_SHIFT);
	if(!vmo)
	{
		vm_destroy_mappings((void *) vm->base, pages);
		return NULL;
	}

	vmo->mappings = vm;
	vm->vmo = vmo;

	if(vmo_prefault(vmo, pages << PAGE_SHIFT, 0) < 0)
	{
		vm_destroy_mappings(vm, pages);
		return NULL;	
	}

	return (void *) vm->base;
}

void vfree(void *ptr, size_t pages)
{
	vm_destroy_mappings(ptr, pages);
}

int vm_check_pointer(void *addr, size_t needed_space)
{
	struct vm_region *e = vm_find_region(addr);
	if(!e)
		return -1;
	if((uintptr_t) addr + needed_space <= e->base + e->pages * PAGE_SIZE)
		return 0;
	else
		return -1;
}

void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t off)
{
	struct vm_region *area = NULL;
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
		area = vm_allocate_virt_region(VM_ADDRESS_USER, pages,
			VM_TYPE_SHARED, vm_prot);
	}
	else
	{
		area = vm_reserve_address(addr, pages, VM_TYPE_REGULAR, vm_prot);
		if(!area)
		{
			if(flags & MAP_FIXED)
				return (void*) -ENOMEM;
			area = vm_allocate_virt_region(VM_ADDRESS_USER, pages, VM_TYPE_REGULAR, vm_prot);
		}
	}

	if(!area)
		return (void*) -ENOMEM;

	if(!(flags & MAP_ANONYMOUS))
	{
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

	if(setup_vmregion_backing(area, pages, !(flags & MAP_ANONYMOUS)) < 0)
			return (void *) -ENOMEM;

	return (void *) area->base;
}


int sys_munmap(void *addr, size_t length)
{
	return 0;
	printk("munmap %p %lu\n", addr, length);
	if (is_higher_half(addr))
		return -EINVAL;

	size_t pages = length / PAGE_SIZE;
	if(length % PAGE_SIZE)
		pages++;
	
	if((unsigned long) addr & (PAGE_SIZE - 1))
		return -EINVAL;

	__vm_lock(false);	
	
	vm_destroy_mappings(addr, length);
	__vm_unlock(false);

	return 0;
}

int sys_mprotect(void *addr, size_t len, int prot)
{
	printk("mprotect %p\n", addr);
	if(is_higher_half(addr))
		return -EINVAL;
	struct vm_region *area = NULL;

	if(!(area = vm_find_region(addr)))
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

	size_t pages = vm_align_size_to_pages(len);

	/* TODO: Doesn't support mprotects that span multiple regions */

	len = pages * PAGE_SIZE; /* Align len on a page boundary */
	#if 0
	if(area->base == (uintptr_t) addr && area->pages * PAGE_SIZE == len)
	{
		area->rwx = vm_prot;
	}
	else if(area->base == (uintptr_t) addr && area->pages * PAGE_SIZE > len)
	{
		uintptr_t second_half = (uintptr_t) addr + len;
		size_t rest_pages = area->pages - pages;
		int old_rwx = area->rwx;
		avl_node_t *node = *avl_search_key(vm_get_tree(), (uintptr_t) addr);
		node->end -= area->pages * PAGE_SIZE - len;
		area->pages = pages;
		area->rwx = vm_prot;

		struct vm_region *new = avl_insert_key(vm_get_tree(), second_half, rest_pages * PAGE_SIZE);
		if(!new)
			return -ENOMEM;
		
		memcpy(new, area, sizeof(struct vm_region));
		new->base = second_half;
		new->pages = rest_pages;
		new->rwx = old_rwx;
	}
	else if(area->base < (uintptr_t) addr && area->base + area->pages * PAGE_SIZE > (uintptr_t) addr + len)
	{
		size_t total_pages = area->pages;
		avl_node_t *node = *avl_search_key(vm_get_tree(), area->base);
		node->end -= (uintptr_t) addr - area->base;
		area->pages = ((uintptr_t) addr - area->base) / PAGE_SIZE;

		struct vm_region *second_area = avl_insert_key(vm_get_tree(), (uintptr_t) addr, (uintptr_t) len);
		if(!second_area)
		{
			/* TODO: Unsafe to just return, maybe restore the old area? */
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
		memcpy(second_area, area, sizeof(struct vm_region));

		second_area->base = (uintptr_t) addr;
		second_area->pages = pages;
		second_area->type = area->type;
		second_area->rwx = vm_prot;

		struct vm_region *third_area = avl_insert_key(vm_get_tree(), (uintptr_t) addr + len, 
		(uintptr_t) total_pages * PAGE_SIZE);
		if(!third_area)
		{
			/* TODO: Unsafe to just return, maybe restore the old area? */
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
		memcpy(third_area, area, sizeof(struct vm_region));
		third_area->base = (uintptr_t) addr + len;
		third_area->pages = total_pages - pages - area->pages;
		third_area->type = area->type;
		third_area->rwx = area->rwx;
	}
	else if(area->base < (uintptr_t) addr && (uintptr_t) addr + len == area->base + area->pages * PAGE_SIZE)
	{
		area->pages -= pages;
		avl_node_t *node = *avl_search_key(vm_get_tree(), (uintptr_t) addr);
		node->end -= pages * PAGE_SIZE;
		struct vm_region *new_area = avl_insert_key(vm_get_tree(), (uintptr_t) addr, len);
		if(!new_area)
		{
			area->pages += pages;
			__vm_unlock(false);
			return errno = -ENOMEM;
		}
		memcpy(new_area, area, sizeof(struct vm_region));
		new_area->base = (uintptr_t) addr;
		new_area->pages = pages;
		new_area->type = area->type;
		new_area->rwx = vm_prot;
	}
	#else
	panic("implement");
	#endif
	__vm_unlock(false);
	vm_change_perms(addr, pages, vm_prot);

	return 0;
}

int do_inc_brk(void *oldbrk, void *newbrk)
{
	void *oldpage = page_align_up(oldbrk);
	void *newpage = page_align_up(newbrk);

	size_t pages = ((uintptr_t) newpage - (uintptr_t) oldpage) / PAGE_SIZE;
	if(vm_map_range(oldpage, pages, VM_WRITE | VM_USER | VM_NOEXEC) == NULL)
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

void print_vm_structs(void *node)
{
	#if 0
	if(node->left)
		print_vm_structs(node->left);
	if(!node->data)
	{
		printk("Found corrupted node at %p\n", node);
		void *phys = virtual2phys(node);
		struct page *p = phys_to_page((uintptr_t) phys & ~(PAGE_SIZE - 1));
		printk("phys %p\n", phys);
		printk("Bad page %p, refcount %lu, next %p\n", p->paddr, p->ref,
			p->next_un.next_virtual_region);
		while(1);
	}

	printk("[Base %016lx Length %016lx End %016lx]\n", node->data->base, node->data->pages
		* PAGE_SIZE, (uintptr_t) node->data->base + node->data->pages * PAGE_SIZE);
	if(node->right)
		print_vm_structs(node->right);
	#endif
}

void vm_print_stats(void)
{
	//struct process *current = get_current_process();
	/*if(current)
		print_vm_structs(current->address_space.tree);
	print_vm_structs(kernel_tree);*/
}

void *__map_pages_to_vaddr(struct process *process, void *virt, void *phys,
		size_t size, size_t flags)
{
	size_t pages = vm_align_size_to_pages(size);
	
#ifdef DEBUG_PRINT_MAPPING
	printk("__map_pages_to_vaddr: %p (phys %p) - %lx\n", virt, phys, (unsigned long) virt + size);
#endif
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

void *mmiomap(void *phys, size_t size, size_t flags)
{
	uintptr_t u = (uintptr_t) phys;
	uintptr_t p_off = u & (PAGE_SIZE - 1);

	size_t pages = vm_align_size_to_pages(size);
	if(p_off)
	{
		pages++;
		size += p_off;
	}

	struct vm_region *entry = vm_allocate_virt_region(
		flags & VM_USER ? VM_ADDRESS_USER : VM_KERNEL,
		 pages, VM_TYPE_REGULAR, flags);
	if(!entry)
	{
		printf("mmiomap: Could not allocate virtual range\n");
		return NULL;
	}

	u &= ~(PAGE_SIZE - 1);

	/* TODO: Clean up if something goes wrong */
	void *p = map_pages_to_vaddr((void *) entry->base, (void *) u,
				     size, flags);
	if(!p)
	{
		printf("map_pages_to_vaddr: Could not map pages\n");
		return NULL;
	}

	return (void *) ((uintptr_t) p + p_off);
}

int __vm_handle_pf(struct vm_region *entry, struct fault_info *info)
{
	ENABLE_INTERRUPTS();
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

int vm_handle_page_fault(struct fault_info *info)
{
	struct vm_region *entry = vm_find_region((void*) info->fault_address);
	if(!entry)
	{
		struct process *current = get_current_process();
		struct thread *ct = get_current_thread();
		printk("Curr thread: %p\n", ct);
		printk("Could not find %lx, ip %lx, process name %s\n", info->fault_address,
			info->ip, current->cmd_line);
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

static void vm_destroy_area(void *key, void *datum)
{
	struct vm_region *region = datum;

	vm_region_destroy(region);
}

void vm_destroy_addr_space(struct mm_address_space *mm)
{
	struct process *current = mm->process;

	/* First, iterate through the rb tree and free/unmap stuff */

	rb_tree_free(mm->area_tree, vm_destroy_area);

	/* We're going to swap our address space to init's, and free our own */
	
	void *own_addrspace = current->address_space.cr3;

	current->address_space.cr3 = vm_get_fallback_cr3();

	paging_load_cr3(mm->cr3);

	free_page(phys_to_page((uintptr_t) own_addrspace));
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
void *vm_gen_mmap_base(void)
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

void *vm_gen_brk_base(void)
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
	if(vm_check_pointer(memstat, sizeof(struct memstat)) < 0)
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

ssize_t vm_traverse_kmaps(void *node, char *address, size_t *size, off_t off)
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
	return 0;
	#if 0
	return vm_traverse_kmaps(kernel_tree, buffer, &size, 0);
	#endif
}

void vm_sysfs_init(void)
{
	INFO("vmm", "Setting up /sys/vm, /sys/vm_aslr and /sys/kmaps\n");
	struct inode *sysfs = open_vfs(get_fs_root(), "/sys");
	if(!sysfs)
		panic("vm_sysfs_init: /sys not mounted!\n");
	struct sysfs_file *vmfile = sysfs_create_entry("vm", 0666, sysfs);
	if(!vmfile)
		panic("vm_sysfs_init: Could not create /sys/vm\n");
	
	struct sysfs_file *aslr_control = sysfs_create_entry("vm_aslr", 0666, sysfs);
	if(!aslr_control)
		panic("vm_sysfs_init: Could not create /sys/vm_aslr\n");
	aslr_control->read = aslr_read;
	aslr_control->write = aslr_write;

	struct sysfs_file *kmaps = sysfs_create_entry("kmaps", 0400, sysfs);
	if(!kmaps)
		panic("vm_sysfs_init: Could not create /sys/kmaps\n");
	kmaps->read = kmaps_read;
}

int vm_mark_cow(struct vm_region *area)
{
	/* If the area isn't writable, don't mark it as COW */
	if(!(area->rwx & VM_WRITE))
		return errno = EINVAL, -1;
	area->flags |= VM_COW;
	return 0;
}

struct vm_region *vm_find_region_and_writable(void *usr)
{
	struct vm_region *entry = vm_find_region(usr);
	if(unlikely(!entry))	return NULL;
	if(likely(entry->rwx & VM_WRITE))	return entry;

	return NULL;
}

struct vm_region *vm_find_region_and_readable(void *usr)
{
	struct vm_region *entry = vm_find_region(usr);
	if(unlikely(!entry))	return NULL;
	return entry;
}

ssize_t copy_to_user(void *usr, const void *data, size_t len)
{
	char *usr_ptr = usr;
	const char *data_ptr = data;
	while(len)
	{
		struct vm_region *entry;
		if((entry = vm_find_region_and_writable(usr_ptr)) == NULL)
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
		struct vm_region *entry;
		if((entry = vm_find_region_and_readable((void*) usr_ptr)) == NULL)
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
		struct vm_region *entry;
		if((entry = vm_find_region_and_readable((void*) usr_ptr)) == NULL)
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
		ENABLE_INTERRUPTS();
		while(1);
		kernel_raise_signal(SIGSEGV, get_current_process());
	}
	else
		panic("Unable to satisfy paging request");
}

void *get_pages(size_t flags, uint32_t type, size_t pages, size_t prot, uintptr_t alignment)
{
	struct vm_region *va = vm_allocate_virt_region(flags, pages, type, prot);
	if(!va)
		return NULL;

	void *address = (void *) va->base;
	if(!(flags & VM_ADDRESS_USER))
	{
		struct page *p = vm_map_range(address, pages, prot);
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

	return address;
}

void *get_user_pages(uint32_t type, size_t pages, size_t prot)
{
	return get_pages(VM_ADDRESS_USER, type, pages, prot | VM_USER, 0);
}

struct page *vmo_commit_file(size_t off, struct vm_object *vmo)
{
	struct page *page = alloc_page(0);
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

	page_ref(p);
	return p;
}

int setup_vmregion_backing(struct vm_region *region, size_t pages, bool is_file_backed)
{
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

bool is_mapping_shared(struct vm_region *region)
{
	return region->mapping_type == MAP_SHARED;
}

bool is_file_backed(struct vm_region *region)
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
		if(!vm_reserve_address(addr, pages, VM_TYPE_REGULAR, prot))
		{
			if(flags & VM_MMAP_FIXED)
				return NULL;
			if(!(addr = get_user_pages(VM_TYPE_REGULAR, pages, prot)))
			{
				return NULL;
			}
		}
	}

	struct vm_region *entry = vm_find_region(addr);
	assert(entry != NULL);

	/* TODO: Maybe we shouldn't use MMAP flags and use these new ones instead? */
	int mmap_like_type =  flags & VM_MMAP_PRIVATE ? MAP_PRIVATE : MAP_SHARED;
	entry->mapping_type = mmap_like_type;
	entry->type = VM_TYPE_FILE_BACKED;
	entry->offset = off;
	//printk("Created file mapping at %lx for off %lu\n", entry->base, off);
	entry->fd = fd;
	fd->refcount++;

	if(setup_vmregion_backing(entry, pages, true) < 0)
		return NULL;
	return addr;
}

void *map_user(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	struct vm_region *en = vm_reserve_address(addr, pages, type, prot);
	if(!en)
		return NULL;
	if(setup_vmregion_backing(en, pages, false) < 0)
		return NULL;
	return addr;
}

void *map_page_list(struct page *pl, size_t size, uint64_t prot)
{
	struct vm_region *entry = vm_allocate_virt_region(VM_KERNEL,
		vm_align_size_to_pages(size), VM_TYPE_REGULAR, prot);
	if(!entry)
		return NULL;
	void *vaddr = (void *) entry->base;

	uintptr_t u = (uintptr_t) vaddr;
	while(pl != NULL)
	{
		if(!map_pages_to_vaddr((void *) u, pl->paddr, PAGE_SIZE, prot))
		{
			vm_destroy_mappings(vaddr, vm_align_size_to_pages(size));
			return NULL;
		}

		pl = pl->next_un.next_allocation;
		u += PAGE_SIZE;
	}

	return vaddr;
}

int vm_create_address_space(struct process *process, void *cr3)
{
	struct mm_address_space *mm = &process->address_space;

	mm->cr3 = cr3;
	mm->mmap_base = vm_gen_mmap_base();
	mm->start = arch_low_half_min;
	mm->end = arch_low_half_max;
	mm->process = process;
	mm->area_tree = rb_tree_new(vm_cmp);
	if(!mm->area_tree)
	{
		return -1;
	}

	mm->brk = map_user(vm_gen_brk_base(), 0x20000000, VM_TYPE_HEAP,
		VM_WRITE | VM_NOEXEC | VM_USER);
	
	if(!mm->brk)
		return -1;

	return 0;
}


void validate_free(void *p)
{
	unsigned long ptr = (unsigned long) p;

	assert(ptr >= heap_addr);
	assert(ptr <= heap_addr + heap_size);
}

void *vm_get_fallback_cr3(void)
{
	return kernel_address_space.cr3;
}