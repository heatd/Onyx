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
#include <onyx/arch.h>
#include <onyx/percpu.h>
#include <onyx/user.h>
#include <onyx/timer.h>

#include <libdict/dict.h>

#include <onyx/mm/vm_object.h>
#include <onyx/mm/kasan.h>
#include <onyx/pagecache.h>

#include <onyx/vm_layout.h>

#include <sys/mman.h>

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
size_t heap_size = 0;

int setup_vmregion_backing(struct vm_region *region, size_t pages, bool is_file_backed);
int populate_shared_mapping(void *page, struct file *fd,
	struct vm_region *entry, size_t nr_pages);
void vm_remove_region(struct mm_address_space *as, struct vm_region *region);
int vm_add_region(struct mm_address_space *as, struct vm_region *region);
void remove_vmo_from_private_list(struct mm_address_space *mm, struct vm_object *vmo);
void add_vmo_to_private_list(struct mm_address_space *mm, struct vm_object *vmo);
bool vm_using_shared_optimization(struct vm_region *region);

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

static struct page *vm_zero_page = NULL;

struct vm_region *vm_reserve_region(struct mm_address_space *as,
				    unsigned long start, size_t size)
{
	struct vm_region *region = zalloc(sizeof(struct vm_region));
	if(!region)
		return NULL;

	region->base = start;
	region->pages = vm_align_size_to_pages(size);
	region->rwx = 0;

	dict_insert_result res = rb_tree_insert(as->area_tree,
						(void *) start);

	if(res.inserted == false)
	{
		if(res.datum_ptr)
			panic("oopsie");
		free(region);
		return NULL;
	}

	region->mm = as;

	*res.datum_ptr = region;

	increment_vm_stat(region->mm, virtual_memory_size, size);

	return region; 
}

#define DEBUG_VM_1 0
#define DEBUG_VM_2 0
#define DEBUG_VM_3 0

unsigned long vm_allocate_base(struct mm_address_space *as, unsigned long min, size_t size)
{
	if(min < as->start)
		min = as->start;

	rb_itor *it = rb_itor_new(as->area_tree);
	bool node_valid;
	unsigned long last_end = min;
	struct vm_region *f = NULL;

	MUST_HOLD_LOCK(&as->vm_spl);
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
#if DEBUG_VM_3
	if(as == &kernel_address_space && min == kstacks_addr)
	printk("Ptr: %lx\nSize: %lx\n", last_end, size);
#endif
	last_end = last_end < min ? min : last_end;
#if DEBUG_VM_3
	if(as == &kernel_address_space && min == kstacks_addr)
	printk("Ptr: %lx\nSize: %lx\n", last_end, size);
#endif

	return last_end;
}

struct vm_region *vm_allocate_region(struct mm_address_space *as,
				     unsigned long min, size_t size)
{
	unsigned long new_base = vm_allocate_base(as, min, size);

	return vm_reserve_region(as, new_base, size);
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
		spin_lock(&kernel_address_space.vm_spl);
	else
		spin_lock(&get_current_process()->address_space.vm_spl);
}

static inline void __vm_unlock(bool kernel)
{
	if(kernel)
		spin_unlock(&kernel_address_space.vm_spl);
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

#ifdef CONFIG_KASAN
	kasan_alloc_shadow(heap_addr, arch_get_initial_heap_size(), false);
#endif
	heap_set_start(heap_addr);

	vm_addr_init();

	heap_size = arch_heap_get_size() - (heap_addr - heap_addr_no_aslr);
	/* Start populating the address space */
	struct vm_region *v = vm_reserve_region(&kernel_address_space, heap_addr, heap_size);
	if(!v)
	{
		panic("vmm: early boot oom");	
	}

	v->type = VM_TYPE_HEAP;
	v->rwx = VM_NOEXEC | VM_WRITE;

	struct kernel_limits l;
	get_kernel_limits(&l);
	size_t kernel_size = l.end_virt - l.start_virt;

	v = vm_reserve_region(&kernel_address_space, l.start_virt, kernel_size);
	if(!v)
	{
		panic("vmm: early boot oom");	
	}

	v->type = VM_TYPE_REGULAR;
	v->rwx = VM_WRITE;

	vm_zero_page = alloc_page(0);
	assert(vm_zero_page != NULL);

	is_initialized = true;
}

struct page *vm_map_range(void *range, size_t nr_pages, uint64_t flags)
{
	const unsigned long mem = (const unsigned long) range;
	struct page *pages = alloc_pages(nr_pages, 0);
	struct page *p = pages;
	if(!pages)
		goto out_of_mem;

#ifdef DEBUG_PRINT_MAPPING
	printk("vm_map_range: %p - %lx\n", range, (unsigned long) range + nr_pages << PAGE_SHIFT);
#endif

	for(size_t i = 0; i < nr_pages; i++)
	{
		//printf("Mapping %p\n", p->paddr);
		if(!vm_map_page(NULL, mem + (i << PAGE_SHIFT), (uintptr_t) page_to_phys(p), flags))
			goto out_of_mem;
		p = p->next_un.next_allocation;
	}

	return pages;

out_of_mem:
	if(pages)	free_pages(pages);
	return NULL;
}

void do_vm_unmap(void *range, size_t pages)
{
	struct vm_region *entry = vm_find_region(range);
	assert(entry != NULL);

	struct vm_object *vmo = entry->vmo;
	assert(vmo != NULL);

	spin_lock(&vmo->page_lock);

	struct rb_itor it;
	it.node = NULL;

	it.tree = vmo->pages;
	size_t off = entry->offset;
	size_t nr_pages = entry->pages;

	bool node_valid = rb_itor_search_ge(&it, (void *) off);
	while(node_valid)
	{
		struct page *p = *rb_itor_datum(&it);
		
		if(p->off >= off + (nr_pages << PAGE_SHIFT))
			break;
		unsigned long reg_off = p->off - off;
		paging_unmap((void *) (entry->base + reg_off));

		node_valid = rb_itor_next(&it);
	}


	spin_unlock(&vmo->page_lock);

	vm_invalidate_range((unsigned long) range, pages);
}

void __vm_unmap_range(void *range, size_t pages)
{
	do_vm_unmap(range, pages);
}

void vm_unmap_range(void *range, size_t pages)
{
	bool kernel = is_higher_half(range);

	__vm_lock(kernel);

	__vm_unmap_range(range, pages);
	__vm_unlock(kernel);
}

static inline bool inode_requires_wb(struct inode *i)
{
	return i->i_type == VFS_TYPE_FILE;
}

bool vm_mapping_requires_wb(struct vm_region *reg)
{
	return reg->mapping_type == MAP_SHARED && reg->fd &&
		inode_requires_wb(reg->fd->vfs_node);
}

bool vm_mapping_is_anon(struct vm_region *reg)
{
	return reg->vmo->type == VMO_ANON;
}

bool vm_mapping_requires_write_protect(struct vm_region *reg)
{
	if(vm_mapping_requires_wb(reg))
	{
		return true;
	}

	/* Let's start to map anon pages as the zero page read-only */
	if(vm_mapping_is_anon(reg))
		return true;

	return false;
}

void vm_region_destroy(struct vm_region *region)
{
	/* First, unref things */
	if(region->fd)
	{
		//struct inode *ino = region->fd->vfs_node;
		/*if(inode_requires_wb(ino) && region->mapping_type == MAP_SHARED)
		{
			writeback_remove_region(region);
		}*/

		fd_put(region->fd);
	}

	if(region->vmo)
	{
		if(region->vmo->refcount == 1)
		{
			if(!is_mapping_shared(region) && !is_higher_half((void *) region->base))
				remove_vmo_from_private_list(region->mm, region->vmo);
		}

		vmo_remove_mapping(region->vmo, region);
		vmo_unref(region->vmo);
	}

	free(region);
}

void vm_destroy_mappings(void *range, size_t pages)
{
	struct mm_address_space *mm = is_higher_half(range)
				? &kernel_address_space : &get_current_process()->address_space;
	struct vm_region *reg = vm_find_region(range);

	vm_unmap_range(range, pages);

	spin_lock(&mm->vm_spl);

	rb_tree_remove(mm->area_tree, (const void *) reg->base);
	
	vm_region_destroy(reg);

	spin_unlock(&mm->vm_spl);

	decrement_vm_stat(mm, virtual_memory_size, pages << PAGE_SHIFT);
}

unsigned long vm_get_base_address(uint64_t flags, uint32_t type)
{
	bool is_kernel_map = flags & VM_KERNEL;
	struct process *current;
	struct mm_address_space *mm = NULL;
	
	if(!is_kernel_map)
	{
		current = get_current_process();
		assert(current != NULL);
		assert(current->address_space.mmap_base != NULL);
		mm = &current->address_space;
	}

	switch(type)
	{
		case VM_TYPE_SHARED:
		case VM_TYPE_STACK:
		{
			if(is_kernel_map)
				return kstacks_addr;
			else				
				return (uintptr_t) mm->mmap_base;
		}

		case VM_TYPE_MODULE:
		{
			assert(is_kernel_map == true);

			return KERNEL_VIRTUAL_BASE;
		}

		default:
		case VM_TYPE_REGULAR:
		{
			if(is_kernel_map)
				return vmalloc_space;
			else
				return (uintptr_t) mm->mmap_base;
		}
	}
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

	if(region)
	{
		region->rwx = prot;
		region->type = type;
	}

	/* Unlock and return */
	__vm_unlock(allocating_kernel);

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
	struct rb_itor it;
	it.node = NULL;
	it.tree = tree;

	if(!rb_itor_search_le(&it, addr))
		return NULL;
	
	while(true)
	{
		struct vm_region *region = *rb_itor_datum(&it);
		if(region->base <= (unsigned long) addr
			&& region->base + (region->pages << PAGE_SHIFT) > (unsigned long) addr)
		{
			return region;
		}

		if(!rb_itor_next(&it))
		{
			break;
		}
	}

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

int vm_flush_mapping(struct vm_region *mapping, struct process *proc)
{
	struct vm_object *vmo = mapping->vmo;
	
	assert(vmo != NULL);

	size_t nr_pages = mapping->pages;

	size_t off = mapping->offset;
	struct rb_itor it;
	it.node = NULL;

	spin_lock(&vmo->page_lock);

	it.tree = vmo->pages;

	bool node_valid = rb_itor_search_ge(&it, (void *) off);
	while(node_valid)
	{
		struct page *p = *rb_itor_datum(&it);
		
		if(p->off >= off + (nr_pages << PAGE_SHIFT))
			break;
		unsigned long reg_off = p->off - off;
		if(!__map_pages_to_vaddr(proc, (void *) (mapping->base + reg_off), page_to_phys(p),
			PAGE_SIZE, mapping->rwx))
		{
			spin_unlock(&vmo->page_lock);
			return -1;
		}

		node_valid = rb_itor_next(&it);
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

struct vm_object *find_forked_private_vmo(struct vm_object *old, struct mm_address_space *mm)
{
	spin_lock(&mm->private_vmo_lock);

	struct vm_object *vmo = mm->vmo_head;
	struct vm_object *to_ret = NULL;

	while(vmo)
	{
		if(vmo->forked_from == old)
		{
			to_ret = vmo;
			goto out;
		}
		vmo = vmo->next_private;
	}

out:
	spin_unlock(&mm->private_vmo_lock);
	return to_ret;
}

#define DEBUG_FORK_VM 0
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
	dict_insert_result res = rb_tree_insert(it->target_mm->area_tree, (void *) key);

	if(!res.inserted)
	{
		free(new_region);
		goto ohno;
	}

	if(new_region->fd) fd_get(new_region->fd);

	*res.datum_ptr = new_region;
	bool vmo_failure = false;
	bool is_private = !is_mapping_shared(new_region);
	bool using_shared_optimization = vm_using_shared_optimization(new_region);
	bool needs_to_fork_memory = is_private && !using_shared_optimization;
	/*bool needs_wb =
		new_region->fd && inode_requires_wb(new_region->fd->vfs_node) &&
		new_region->mapping_type == MAP_SHARED;*/

	if(needs_to_fork_memory)
	{
		new_region->vmo = find_forked_private_vmo(new_region->vmo, it->target_mm);
		assert(new_region->vmo != NULL);
		vmo_ref(new_region->vmo);
		vmo_assign_mapping(new_region->vmo, new_region);
	}
	else
	{
		vmo_ref(new_region->vmo);
		vmo_assign_mapping(new_region->vmo, new_region);
		
	//	if(needs_wb)	writeback_add_region(new_region);
	}

	if(vmo_failure)
	{
		dict_remove_result res = rb_tree_remove(it->target_mm->area_tree, key);
		assert(res.removed == true);
		//if(needs_wb)	writeback_remove_region(new_region);
		free(new_region);
		goto ohno;
	}

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

int vm_fork_private_vmos(struct mm_address_space *mm)
{
	struct mm_address_space *parent_mm = get_current_address_space();
	spin_lock(&parent_mm->private_vmo_lock);

	struct vm_object *vmo = parent_mm->vmo_head;

	while(vmo)
	{
		struct vm_object *new_vmo = vmo_fork(vmo, false, NULL);
		if(!new_vmo)
		{
			spin_unlock(&parent_mm->private_vmo_lock);
			return -1;
		}

		new_vmo->refcount = 0;
		add_vmo_to_private_list(mm, new_vmo);

		vmo = vmo->next_private;
	}

	spin_unlock(&parent_mm->private_vmo_lock);
	return 0;
}

int vm_fork_address_space(struct mm_address_space *addr_space)
{
	__vm_lock(false);

	if(vm_fork_private_vmos(addr_space) < 0)
	{
		__vm_unlock(false);
		return -1;
	}

	struct fork_iteration it = {};
	it.target_mm = addr_space;
	it.success = true;

	if(paging_fork_tables(addr_space) < 0)
	{
		__vm_unlock(false);
		return -1;
	}

	struct mm_address_space *current_mm = get_current_address_space();

	addr_space->area_tree = rb_tree_new(vm_cmp);

	if(!addr_space->area_tree)
	{
		tear_down_addr_space(addr_space);
		__vm_unlock(false);
		return -1;
	}

	rb_tree_traverse(current_mm->area_tree, fork_vm_region, (void *) &it);

	if(!it.success)
	{
		tear_down_addr_space(addr_space);
		__vm_unlock(false);
		return -1;
	}

	addr_space->resident_set_size = current_mm->resident_set_size;
	addr_space->shared_set_size = current_mm->shared_set_size;
	addr_space->virtual_memory_size = current_mm->virtual_memory_size;

	__vm_unlock(false);
	return 0;
}

void vm_change_perms(void *range, size_t pages, int perms)
{
	struct mm_address_space *as;
	bool kernel = is_higher_half(range);
	bool needs_release = false;
	if(kernel)
		as = &kernel_address_space;
	else
		as = &get_current_process()->address_space;

	if(!spin_lock_held(&as->vm_spl))
	{
		needs_release = true;
		spin_lock(&as->vm_spl);
	}

	for(size_t i = 0; i < pages; i++)
	{
		paging_change_perms(range, perms);

		range = (void *)((unsigned long) range + PAGE_SIZE);
	}

	vm_invalidate_range((unsigned long) range, pages);

	
	if(needs_release)
		spin_unlock(&as->vm_spl);
}

void *vmalloc(size_t pages, int type, int perms)
{
	struct vm_region *vm =
		vm_allocate_virt_region(VM_KERNEL, pages, type, perms);
	if(!vm)
		return NULL;

	struct vm_object *vmo = vmo_create_phys(pages << PAGE_SHIFT);
	if(!vmo)
	{
		vm_destroy_mappings((void *) vm->base, pages);
		return NULL;
	}

	vmo_assign_mapping(vmo, vm);

	vm->vmo = vmo;

	if(vmo_prefault(vmo, pages << PAGE_SHIFT, 0) < 0)
	{
		/* FIXME: This code doesn't seem correct */
		vmo_remove_mapping(vmo, vm);
		vmo_unref(vmo);
		vm->vmo = NULL;
		vm_destroy_mappings(vm, pages);
		return NULL;
	}

	if(vm_flush(vm) < 0)
	{
		/* FIXME: Same as above */
		vmo_remove_mapping(vmo, vm);
		vmo_unref(vmo);
		vm_destroy_mappings(vm, pages);
		return NULL;
	}
 
 #ifdef CONFIG_KASAN
	kasan_alloc_shadow(vm->base, pages << PAGE_SHIFT, true);
#endif
	return (void *) vm->base;
}

void vfree(void *ptr, size_t pages)
{
	vm_munmap(&kernel_address_space, ptr, pages << PAGE_SHIFT);
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
	/* FIXME: Lots of this code needs correct error paths */
	int error = 0;

	struct vm_region *area = NULL;
	struct file *file_descriptor = NULL;
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
		file_descriptor = get_file_description(fd);
		if(!file_descriptor)
			return (void *) (unsigned long) -errno;

		bool fd_has_write = !(file_descriptor->flags & O_WRONLY) &&
				    !(file_descriptor->flags & O_RDWR);
		if(fd_has_write && prot & PROT_WRITE
		&& flags & MAP_SHARED)
		{
			/* You can't map for writing on a file without read access with MAP_SHARED! */
			error = -EACCES;
			goto out_error;
		}
	}

	/* Calculate the pages needed for the overall size */
	size_t pages = vm_align_size_to_pages(length);
	int vm_prot = VM_USER |
		      ((prot & PROT_WRITE) ? VM_WRITE : 0) |
		      ((!(prot & PROT_EXEC)) ? VM_NOEXEC : 0);

	if(is_higher_half(addr)) /* User addresses can't be on the kernel's address space */
	{
		if(flags & MAP_FIXED)
		{
			error = -ENOMEM;
			goto out_error;
		}
		
		addr = NULL;
	}

	if(!addr)
	{
		if(flags & MAP_FIXED)
		{
			error = -ENOMEM;
			goto out_error;
		}
		/* Specified by POSIX, if addr == NULL, guess an address */
		area = vm_allocate_virt_region(VM_ADDRESS_USER, pages,
			VM_TYPE_SHARED, vm_prot);
	}
	else
	{
		if(flags & MAP_FIXED)
		{
			struct mm_address_space *mm = &get_current_process()->address_space;
			vm_munmap(mm, addr, pages << PAGE_SHIFT);
		}

		area = vm_reserve_address(addr, pages, VM_TYPE_REGULAR, vm_prot);
		if(!area)
		{
			if(flags & MAP_FIXED)
			{
				error = -ENOMEM;
				goto out_error;
			}

			area = vm_allocate_virt_region(VM_ADDRESS_USER, pages, VM_TYPE_REGULAR, vm_prot);
		}
	}

	if(!area)
	{
		error = -ENOMEM;
		goto out_error;
	}

	if(flags & MAP_SHARED)
		area->mapping_type = MAP_SHARED;
	else
		area->mapping_type = MAP_PRIVATE;

	if(!(flags & MAP_ANONYMOUS))
	{
		//printk("Mapping off %lx, size %lx, prots %x\n", off, length, prot);

		/* Set additional meta-data */

		area->type = VM_TYPE_FILE_BACKED;

		area->offset = off;
		area->fd = file_descriptor;

		/* No need to fd_get here since we already have a reference and we're not
		 * dropping it on success
		*/

		if((file_descriptor->vfs_node->i_type == VFS_TYPE_BLOCK_DEVICE 
		   || file_descriptor->vfs_node->i_type == VFS_TYPE_CHAR_DEVICE)
		   && area->mapping_type == MAP_SHARED)
		{
			struct inode *vnode = file_descriptor->vfs_node;
			if(!vnode->i_fops.mmap)
			{
				return (void *) -ENOSYS;
			}

			return vnode->i_fops.mmap(area, vnode);
		}
	}

	if(setup_vmregion_backing(area, pages, !(flags & MAP_ANONYMOUS)) < 0)
			return (void *) -ENOMEM;

	return (void *) area->base;

out_error:
	if(file_descriptor)	fd_put(file_descriptor);
	return (void *) (unsigned long) error;
}


int sys_munmap(void *addr, size_t length)
{
	if(is_higher_half(addr))
		return -EINVAL;

	size_t pages = vm_align_size_to_pages(length);
	
	if((unsigned long) addr & (PAGE_SIZE - 1))
		return -EINVAL;
	
	struct mm_address_space *mm = &get_current_process()->address_space;

	int ret = vm_munmap(mm, addr, pages << PAGE_SHIFT);

	return ret;
}

void vm_copy_region(const struct vm_region *source, struct vm_region *dest)
{
	dest->fd = source->fd;
	if(dest->fd)
	{
		/*struct inode *ino = dest->fd->vfs_node;
		if(source->mapping_type == MAP_SHARED && inode_requires_wb(ino))
			writeback_add_region(dest);*/
		fd_get(dest->fd);
	}

	dest->flags = source->flags;
	dest->rwx = source->rwx;
	dest->mapping_type = source->mapping_type;
	dest->offset = source->offset;
	dest->mm = source->mm;
	dest->vmo = source->vmo;
	vmo_assign_mapping(dest->vmo, dest);
	vmo_ref(dest->vmo);
	dest->type = source->type;
}

struct vm_region *vm_split_region(struct mm_address_space *as, struct vm_region *region,
				  unsigned long addr,
				  size_t size, size_t *pto_shave_off)
{
	size_t region_size = region->pages << PAGE_SHIFT;
		
	size_t to_shave_off = 0;
	if(region->base == addr)
	{
		to_shave_off = size < region_size ? size : region_size;
		*pto_shave_off = to_shave_off;

		if(to_shave_off != region_size)
		{
			vm_remove_region(as, region);

			off_t old_off = region->offset;

			region->base += to_shave_off;
			region->pages -= to_shave_off >> PAGE_SHIFT;
			region->offset += to_shave_off;
			if(vm_add_region(as, region) < 0)
			{
				return errno = ENOMEM, NULL;
			}

			struct vm_region *reg = vm_reserve_region(as, addr, to_shave_off);

			if(!reg)
			{
				return errno = ENOMEM, NULL;
			}

			/* Essentially, we create a carbon
			 * copy of the region and increment/decrement some values */
			vm_copy_region(region, reg);
			reg->base = addr;
			reg->pages = to_shave_off >> PAGE_SHIFT;

			/* Also, set the offset of the old region */
			reg->offset = old_off;
			return reg;
		}
		else
		{
			return region;
		}
	}
	else if(region->base < addr)
	{
		unsigned long offset = addr - region->base;
		unsigned long remainder = region_size - offset;
		to_shave_off = size < remainder ? size : remainder;
		*pto_shave_off = to_shave_off;

		if(to_shave_off != remainder)
		{
			unsigned long second_region_start = addr + to_shave_off;
			unsigned long second_region_size = remainder - to_shave_off;

			struct vm_region *new_region = vm_reserve_region(as,
					second_region_start,
					second_region_size);

			if(!new_region)
			{
				return errno = ENOMEM, NULL;
			}

			vm_copy_region(region, new_region);
			new_region->offset += offset + to_shave_off;

			struct vm_region *to_ret =
					vm_reserve_region(as, addr, to_shave_off);
			if(!to_ret)
			{
				vm_remove_region(as, new_region);
				return errno = ENOMEM, NULL;
			}

			vm_copy_region(region, to_ret);
			to_ret->offset += offset;
				
			vm_remove_region(as, region);

			/* The original region's size is offset */
			region->pages = offset >> PAGE_SHIFT;

			/* FIXME: it's not clear what we should do on OOM cases
			* This code and munmap's code is riddled with these things. */
			(void) vm_add_region(as, region);

			return to_ret;
		}
		else
		{
			struct vm_region *to_ret =
				vm_reserve_region(as, addr, to_shave_off);
			if(!to_ret)
			{
				return errno = ENOMEM, NULL;
			}

			vm_copy_region(region, to_ret);
			to_ret->offset += offset;

			region->pages -= to_shave_off >> PAGE_SHIFT;
			return to_ret;
		}
	}

	__builtin_unreachable();
}

int vm_mprotect_in_region(struct mm_address_space *as, struct vm_region *region,
			  unsigned long addr, size_t size, int prot, size_t *pto_shave_off)
{
	bool using_shared_optimization = vm_using_shared_optimization(region);
	bool marking_write = prot & VM_WRITE;

	//printk("mprotect %lx - %lx, prot %x\n", addr, addr + size, prot);

	if(marking_write && using_shared_optimization)
	{
		/* Our little MAP_PRIVATE using MAP_SHARED trick will not work
		 * now, so create a new vm object backing
		*/
		panic("implement\n");
	}

	struct vm_region *new_region = vm_split_region(as, region, addr, size, pto_shave_off);
	if(!new_region)
		return -1;

	new_region->rwx = prot;

	return 0;
}

int vm_mprotect(struct mm_address_space *as, void *__addr, size_t size, int prot)
{
	unsigned long addr = (unsigned long) __addr;
	unsigned long limit = addr + size;

	spin_lock(&as->vm_spl);

	while(addr < limit)
	{
		struct vm_region *region = vm_find_region_in_tree((void *) addr, as->area_tree);
		if(!region)
		{
			spin_unlock(&as->vm_spl);
			return -EINVAL;
		}

		size_t to_shave_off = 0;
		int st = vm_mprotect_in_region(as, region, addr, size, prot, &to_shave_off);

		if(st < 0)
		{
			spin_unlock(&as->vm_spl);
			return st;
		}

		vm_change_perms((void *) addr, to_shave_off >> PAGE_SHIFT, prot);

		addr += to_shave_off;
		size -= to_shave_off;
	}

	spin_unlock(&as->vm_spl);

	return 0;
}

int sys_mprotect(void *addr, size_t len, int prot)
{
	if(is_higher_half(addr))
		return -EINVAL;
	struct vm_region *area = NULL;

	if(!(area = vm_find_region(addr)))
	{
		return -EINVAL;
	}

	/* The address needs to be page aligned */
	if((unsigned long) addr & (PAGE_SIZE - 1))
		return -EINVAL;
	
	/* Error on len misalignment */
	if(len & (PAGE_SIZE - 1))
		return -EINVAL;

	int vm_prot = VM_USER |
		      ((prot & PROT_WRITE) ? VM_WRITE : 0) |
		      ((!(prot & PROT_EXEC)) ? VM_NOEXEC : 0);

	size_t pages = vm_align_size_to_pages(len);

	len = pages << PAGE_SHIFT; /* Align len on a page boundary */

	struct process *p = get_current_process();
	//vm_print_umap();
	int st = vm_mprotect(&p->address_space, addr, len, vm_prot);
	//vm_print_umap();
	//while(true) {}
	return st;
}

int vm_expand_brk(size_t nr_pages);

int do_inc_brk(void *oldbrk, void *newbrk)
{
	void *oldpage = page_align_up(oldbrk);
	void *newpage = page_align_up(newbrk);

	size_t pages = ((uintptr_t) newpage - (uintptr_t) oldpage) / PAGE_SIZE;
	
	if(pages > 0)
	{
		return vm_expand_brk(pages);
	}

	return 0;
}

uint64_t sys_brk(void *newbrk)
{
	struct process *p = get_current_process();

	spin_lock(&p->address_space.vm_spl);

	if(newbrk == NULL)
	{
		uint64_t ret = (uint64_t) p->address_space.brk;
		spin_unlock(&p->address_space.vm_spl);
		return ret;
	}

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
		{
			spin_unlock(&p->address_space.vm_spl); 
			return -ENOMEM;
		}

		p->address_space.brk = newbrk;
	}

	uint64_t ret = (uint64_t) p->address_space.brk;
	spin_unlock(&p->address_space.vm_spl); 
	return ret;
}

static bool vm_print(const void *key, void *datum, void *user_data)
{
	struct vm_region *region = datum;
	bool x = !(region->rwx & VM_NOEXEC);
	bool w = region->rwx & VM_WRITE;
	bool file_backed = is_file_backed(region);
	struct file *fd = region->fd;

	printk("[%016lx - %016lx] : %s%s%s\n", region->base,
					       region->base + (region->pages << PAGE_SHIFT),
					       "R", w ? "W" : "-", x ? "X" : "-");
	printk("vmo %p mapped at offset %lx", region->vmo, region->offset);
	if(file_backed)
		printk(" - file backed ino %lu\n", fd->vfs_node->i_inode);
	else
		printk("\n");

	return true;
}

void vm_print_map(void)
{
	rb_tree_traverse(kernel_address_space.area_tree, vm_print, NULL);
}

void vm_print_umap()
{
	rb_tree_traverse(get_current_address_space()->area_tree, vm_print, NULL);
}

#define DEBUG_PRINT_MAPPING 0
void *__map_pages_to_vaddr(struct process *process, void *virt, void *phys,
		size_t size, size_t flags)
{
	size_t pages = vm_align_size_to_pages(size);
	
#if DEBUG_PRINT_MAPPING
	printk("__map_pages_to_vaddr: %p (phys %p) - %lx\n", virt, phys, (unsigned long) virt + size);
#endif
	void *ptr = virt;
	for(uintptr_t virt = (uintptr_t) ptr, _phys = (uintptr_t) phys, i = 0; i < pages; virt += PAGE_SIZE, 
		_phys += PAGE_SIZE, ++i)
	{
		if(!vm_map_page(process, virt, _phys, flags))
			return NULL;
	}

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
#ifdef CONFIG_KASAN
	kasan_alloc_shadow(entry->base, size, true);
#endif
	return (void *) ((uintptr_t) p + p_off);
}

struct vm_pf_context
{
	/* The vm region in question */
	struct vm_region *entry;
	/* This fault's info */
	struct fault_info *info;
	/* vpage - fault_address but page aligned */
	unsigned long vpage;
	/* Page permitions - is prefilled by calling code */
	int page_rwx;
	/* Mapping info if page was present */
	unsigned long mapping_info;
	/* The to-be-mapped page - filled by called code */
	struct page *page;
};

struct page *vm_pf_get_page_from_vmo(struct vm_pf_context *ctx)
{
	struct vm_region *entry = ctx->entry;
	size_t vmo_off = (ctx->vpage - entry->base) + entry->offset;
	ctx->page = vmo_get(entry->vmo, vmo_off, true);

	return ctx->page;
}

int vm_handle_non_present_pf(struct vm_pf_context *ctx)
{
	struct vm_region *entry = ctx->entry;
	struct fault_info *info = ctx->info;

	if(vm_mapping_requires_write_protect(entry))
	{
		assert(info->read ^ info->write);
		if(!info->write)
		{
			/* If we'll need to wp, write-protect */
			ctx->page_rwx &= ~VM_WRITE;
			if(vm_mapping_is_anon(entry))
			{
				ctx->page = vm_zero_page;
			}
		}
		else
		{
			if(vm_mapping_requires_wb(entry))
			{
				/* else handle it differently(we'll need) */
				struct page *p = vm_pf_get_page_from_vmo(ctx);
				if(!p)
				{
					info->error = VM_SIGSEGV;
					return -1;
				}

				pagecache_dirty_block(p->cache);

				ctx->page = p;
			}
			else if(vm_mapping_is_anon(entry))
			{
				/* This is done down there */
			}
		}
	}
	
	/* If page wasn't set before by other fault handling code, just fetch from the vmo */
	if(ctx->page == NULL)
	{
		ctx->page = vm_pf_get_page_from_vmo(ctx);
		if(!ctx->page)
		{
			info->error = VM_SIGSEGV;
			return -1;
		}
	}

	if(!map_pages_to_vaddr((void *) ctx->vpage,
		page_to_phys(ctx->page), PAGE_SIZE, ctx->page_rwx))
	{
		info->error = VM_SIGSEGV;
		return -1;
	}

	return 0;
}

void vm_handle_write_wb(struct vm_pf_context *ctx)
{
	unsigned long paddr = MAPPING_INFO_PADDR(ctx->mapping_info);
	struct page *p = phys_to_page(paddr);

	pagecache_dirty_block(p->cache);

	paging_change_perms((void *) ctx->vpage, ctx->page_rwx);
	vm_invalidate_range(ctx->vpage, 1);
}

int vm_handle_present_pf(struct vm_pf_context *ctx)
{
	struct vm_region *entry = ctx->entry;
	struct fault_info *info = ctx->info;

	if(info->write & !(ctx->mapping_info & PAGE_WRITABLE))
	{
		if(vm_mapping_requires_wb(entry))
			vm_handle_write_wb(ctx);
		if(vm_mapping_is_anon(entry))
		{
			struct page *p = vm_pf_get_page_from_vmo(ctx);
			if(!p)
			{
				info->error = VM_SIGSEGV;
				return -1;
			}

			ctx->page = p;

			if(!map_pages_to_vaddr((void *) ctx->vpage,
				page_to_phys(ctx->page), PAGE_SIZE, ctx->page_rwx))
			{
				info->error = VM_SIGSEGV;
				return -1;
			}
		}
	}

	return 0;
}

void setup_debug_register(unsigned long addr, unsigned int size, unsigned int condition);

int __vm_handle_pf(struct vm_region *entry, struct fault_info *info)
{
	assert(entry->vmo != NULL);
	struct vm_pf_context context;
	context.entry = entry;
	context.info = info;
	context.vpage = info->fault_address & -PAGE_SIZE;
	context.page = NULL;
	context.page_rwx = entry->rwx;
	context.mapping_info = get_mapping_info((void *) context.vpage);

	if(context.mapping_info & PAGE_PRESENT)
	{
		if(vm_handle_present_pf(&context) < 0)
			return -1;
	}
	else
	{
		if(vm_handle_non_present_pf(&context) < 0)
			return -1;
	}

	//printk("elapsed: %lu ns\n", end - start);
	return 0;
}

int vm_handle_page_fault(struct fault_info *info)
{
	ENABLE_INTERRUPTS();

	struct mm_address_space *as = get_current_address_space();

	spin_lock_preempt(&as->vm_spl);

	struct vm_region *entry = vm_find_region((void*) info->fault_address);
	if(!entry)
	{
		struct thread *ct = get_current_thread();
		if(ct && !info->user)
		{
			struct process *current = get_current_process();
			printk("Curr thread: %p\n", ct);
			const char *str;
			if(info->write)
				str = "write";
			else if(info->exec)
				str = "exec";
			else
				str = "read";
			printk("Page fault at %lx, %s, ip %lx, process name %s\n",
				info->fault_address, str, info->ip,
				current ? current->cmd_line : "(kernel)");
		}
		
		info->error = VM_SIGSEGV;
		spin_unlock_preempt(&as->vm_spl);
		return -1;
	}

	if(info->write && !(entry->rwx & VM_WRITE))
		return -1;
	if(info->exec && entry->rwx & VM_NOEXEC)
		return -1;
	if(info->user && !(entry->rwx & VM_USER))
		return -1;


	__sync_add_and_fetch(&as->page_faults, 1);

	int ret = __vm_handle_pf(entry, info);

	spin_unlock_preempt(&as->vm_spl);

#if 0
	if(ret < 0)
	{
		/* Lets send a signal */
		unsigned int sig;
		
		switch(info->error)
		{
			case VM_SIGBUS:
				sig = SIGBUS;
				break;
			case VM_SIGSEGV:
			default:
				sig = SIGSEGV;
				break;
		}

		kernel_tkill(sig, get_current_thread());
	}
#endif
	return ret;
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
	spin_lock(&mm->vm_spl);
	rb_tree_free(mm->area_tree, vm_destroy_area);
	spin_lock_held(&mm->vm_spl);

	/* We're going to swap our address space to init's, and free our own */
	
	void *own_addrspace = current->address_space.cr3;

	current->address_space.cr3 = vm_get_fallback_cr3();

	paging_load_cr3(mm->cr3);

	free_page(phys_to_page((uintptr_t) own_addrspace));
	spin_unlock(&mm->vm_spl);
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
	struct memstat buf;
	page_get_stats(&buf);

	if(copy_to_user(memstat, &buf, sizeof(buf)) < 0)
		return -EFAULT;
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

char *strcpy_from_user(const char *uptr)
{
	size_t len = strlen_user(uptr);
	if(len == (size_t) -EFAULT)
	{
		errno = EFAULT;
		return NULL;
	}

	char *buf = malloc(len + 1);
	if(!buf)
		return NULL;
	buf[len] = '\0';

	if(copy_from_user(buf, uptr, len) < 0)
	{
		free(buf);
		errno = EFAULT;
		return NULL;
	}

	return buf;
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
#ifdef CONFIG_KASLR
	if(bits != 0)
		bits--;
	uintptr_t mask = UINTPTR_MAX & ~(-(1UL << bits));
	/* Get entropy from arc4random() */
	uintptr_t result = ((uintptr_t) arc4random() << 12) & mask;
	result |= ((uintptr_t) arc4random() << 44) & mask;

	base |= result;
#endif
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
		printk("Program base: %p\n", current->image_base);

		kernel_raise_signal(SIGSEGV, get_current_process());
	}
	else
		panic("Unable to satisfy paging request");
}

void *get_pages(size_t flags, uint32_t type, size_t pages, size_t prot, uintptr_t alignment)
{
	bool kernel = !(flags & VM_ADDRESS_USER);

	struct vm_region *va = vm_allocate_virt_region(flags, pages, type, prot);
	if(!va)
		return NULL;
	
	if(setup_vmregion_backing(va, pages, false) < 0)
	{
		vm_munmap(va->mm, (void *) va->base, pages << PAGE_SHIFT);
		return NULL;
	}

	if(kernel)
	{
		if(vmo_prefault(va->vmo, pages << PAGE_SHIFT, 0) < 0)
		{
			vm_munmap(&kernel_address_space, (void *) va->base, pages << PAGE_SHIFT);
			return NULL;
		}

		if(vm_flush(va) < 0)
		{
			vmo_remove_mapping(va->vmo, va);
			vmo_unref(va->vmo);
			vm_destroy_mappings(va, pages);
			return NULL;
		}
#ifdef CONFIG_KASAN
		kasan_alloc_shadow(va->base, pages << PAGE_SHIFT, true);
#endif
	}

	return (void *) va->base;
}

void *get_user_pages(uint32_t type, size_t pages, size_t prot)
{
	return get_pages(VM_ADDRESS_USER, type, pages, prot | VM_USER, 0);
}

struct page *vm_commit_private(size_t off, struct vm_object *vmo)
{
	struct page *p = alloc_page(0);
	if(!p)
		return NULL;
	struct inode *ino = vmo->ino;
	off_t file_off = (off_t) vmo->priv;

	//printk("commit %lx\n", off + file_off);
	size_t read = read_vfs(0, off + file_off, PAGE_SIZE, PAGE_TO_VIRT(p), ino);

	if((ssize_t) read < 0)
	{
		free_page(p);
		return NULL;
	}

	return p;
}

void add_vmo_to_private_list(struct mm_address_space *mm, struct vm_object *vmo)
{
	spin_lock(&mm->private_vmo_lock);

	if(!mm->vmo_head)
	{
		mm->vmo_head = mm->vmo_tail = vmo;
		vmo->prev_private = vmo->next_private = NULL;
	}
	else
	{
		struct vm_object *old_tail = mm->vmo_tail;
		old_tail->next_private = vmo;
		vmo->prev_private = old_tail;
		vmo->next_private = NULL;
		mm->vmo_tail = vmo;
	}

	spin_unlock(&mm->private_vmo_lock);
}

void remove_vmo_from_private_list(struct mm_address_space *mm, struct vm_object *vmo)
{
	spin_lock(&mm->private_vmo_lock);

	bool is_head = vmo->prev_private == NULL;
	bool is_tail = vmo->next_private == NULL;

	if(is_head && is_tail)
		mm->vmo_head = mm->vmo_tail = NULL;
	else if(is_head)
	{
		mm->vmo_head = vmo->next_private;
		if(mm->vmo_head)
			mm->vmo_head->prev_private = NULL;
	}
	else if(is_tail)
	{
		mm->vmo_tail = vmo->prev_private;
		if(mm->vmo_tail)
			mm->vmo_tail->next_private = NULL;
	}
	else
	{
		vmo->prev_private->next_private = vmo->next_private;
		vmo->next_private->prev_private = vmo->prev_private;
	}

	spin_unlock(&mm->private_vmo_lock);
}

bool can_use_map_shared_optimization(struct vm_region *region)
{
	/* So, basically in order to map shared pages in a MAP_PRIVATE
	 * we need to make sure that off is page aligned and that the region is not writable
	*/
	off_t off = region->offset;
	if((off & (PAGE_SIZE - 1)) != 0)
		return false;
	if(region->rwx & VM_WRITE)
		return false;
	return true;
}

bool vm_using_shared_optimization(struct vm_region *region)
{
	return region->flags & VM_USING_MAP_SHARED_OPT;
}

int setup_vmregion_backing(struct vm_region *region, size_t pages, bool is_file_backed)
{
	bool is_shared = is_mapping_shared(region);
	bool is_kernel = is_higher_half((void *) region->base);
	bool can_use_shared_optimization = can_use_map_shared_optimization(region);
	struct vm_object *vmo;

	if(is_file_backed && (is_shared || can_use_shared_optimization))
	{
		struct inode *ino = region->fd->vfs_node;

		spin_lock(&ino->i_pages_lock);

		if(!ino->i_pages)
		{
			if(inode_create_vmo(ino) < 0)
			{
				spin_unlock(&ino->i_pages_lock);
				return -1;
			}
		}

		vmo_ref(ino->i_pages);
		vmo = ino->i_pages;

		spin_unlock(&ino->i_pages_lock);
		if(can_use_shared_optimization)
		{
			region->flags |= VM_USING_MAP_SHARED_OPT;
			//printk("using optimization\n");
		}
	}
	else if(is_file_backed && !is_shared)
	{
		/* store the offset in vmo->priv */
		vmo = vmo_create(pages * PAGE_SIZE, (void *) region->offset);
		if(!vmo)
			return -1;
		vmo->ino = region->fd->vfs_node;
		vmo->commit = vm_commit_private;
		region->offset = 0;
	}
	else
		vmo = vmo_create_phys(pages * PAGE_SIZE);

	if(!vmo)
		return -1;

	vmo_assign_mapping(vmo, region);

	if(!(is_shared || can_use_shared_optimization) && !is_kernel)
	{
		struct mm_address_space *mm = &get_current_process()->address_space;

		add_vmo_to_private_list(mm, vmo);
	}

	if(is_shared)
		increment_vm_stat(region->mm, shared_set_size, vmo->size);

	assert(region->vmo == NULL);
	region->vmo = vmo;
	return 0;
}

bool is_mapping_shared(struct vm_region *region)
{
	return region->mapping_type == MAP_SHARED || region->flags & VM_USING_MAP_SHARED_OPT;
}

bool is_file_backed(struct vm_region *region)
{
	return region->type == VM_TYPE_FILE_BACKED;
}

void *create_file_mapping(void *addr, size_t pages, int flags,
	int prot, struct file *fd, off_t off)
{
	struct vm_region *entry = NULL;
	if(!addr)
	{
		panic("todo");
		if(!(addr = get_user_pages(VM_TYPE_REGULAR, pages, prot)))
		{
			return NULL;
		}
	}
	else
	{
		if(!(entry = vm_reserve_address(addr, pages, VM_TYPE_REGULAR, prot)))
		{
			vm_munmap(get_current_address_space(), addr, pages << PAGE_SHIFT);
			if((entry = vm_reserve_address(addr, pages, VM_TYPE_REGULAR, prot)))
				goto good;

			if(flags & VM_MMAP_FIXED)
				return NULL;
			panic("todo");
			if(!(addr = get_user_pages(VM_TYPE_REGULAR, pages, prot)))
			{
				return NULL;
			}
		}
	}
good: ;
	assert(entry != NULL);

	/* TODO: Maybe we shouldn't use MMAP flags and use these new ones instead? */
	int mmap_like_type =  flags & VM_MMAP_PRIVATE ? MAP_PRIVATE : MAP_SHARED;
	entry->mapping_type = mmap_like_type;
	entry->type = VM_TYPE_FILE_BACKED;
	entry->offset = off;
	//printk("Created file mapping at %lx for off %lu\n", entry->base, off);
	entry->fd = fd;
	fd_get(fd);
	/*bool wants_wb = inode_requires_wb(entry->fd->vfs_node) && mmap_like_type == MAP_SHARED; 
	if(wants_wb)
		writeback_add_region(entry);*/

	if(setup_vmregion_backing(entry, pages, true) < 0)
	{
		/*if(wants_wb)
			writeback_remove_region(entry);*/
		return NULL;
	}
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
		if(!map_pages_to_vaddr((void *) u, page_to_phys(pl), PAGE_SIZE, prot))
		{
			vm_destroy_mappings(vaddr, vm_align_size_to_pages(size));
			return NULL;
		}

		pl = pl->next_un.next_allocation;
		u += PAGE_SIZE;
	}
#ifdef CONFIG_KASAN
	kasan_alloc_shadow((unsigned long) vaddr, size, true);
#endif

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
	mm->resident_set_size = 0;
	mm->shared_set_size = 0;
	mm->virtual_memory_size = 0;
	mm->area_tree = rb_tree_new(vm_cmp);

	if(!mm->area_tree)
	{
		return -1;
	}

	mm->brk = map_user(vm_gen_brk_base(), 1, VM_TYPE_HEAP,
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

void vm_remove_region(struct mm_address_space *as, struct vm_region *region)
{
	dict_remove_result res = rb_tree_remove(as->area_tree,
						 (const void *) region->base);
	assert(res.removed == true);
}

int vm_add_region(struct mm_address_space *as, struct vm_region *region)
{
	dict_insert_result res = rb_tree_insert(as->area_tree, (void *) region->base);

	if(!res.inserted)
		return -1;
	*res.datum_ptr = (void *) region;

	return 0;
}

void vm_unmap_range_raw(void *range, size_t size)
{
	unsigned long addr = (unsigned long) range;
	unsigned long end = addr + size;
	while(addr < end)
	{
		paging_unmap((void *) addr);

		addr += PAGE_SIZE;
	}

	vm_invalidate_range((unsigned long) range, size >> PAGE_SHIFT);
}

int vm_munmap(struct mm_address_space *as, void *__addr, size_t size)
{
	size = ALIGN_TO(size, PAGE_SIZE);
	unsigned long addr = (unsigned long) __addr;
	unsigned long limit = addr + size;

	spin_lock(&as->vm_spl);

	//printk("munmap %lx, %lx\n", addr, limit);

	while(addr < limit)
	{
		struct vm_region *region = vm_find_region_in_tree((void *) addr, as->area_tree);
		if(!region)
		{
			spin_unlock(&as->vm_spl);
			return -EINVAL;
		}

		bool is_shared = is_mapping_shared(region);

		__vm_unmap_range((void *) addr, (limit - addr) >> PAGE_SHIFT);

		size_t region_size = region->pages << PAGE_SHIFT;
		
		size_t to_shave_off = 0;
		if(region->base == addr)
		{
			to_shave_off = size < region_size ? size : region_size;

			if(to_shave_off != region_size)
			{
				vm_remove_region(as, region);

				region->base += to_shave_off;
				region->pages -= to_shave_off >> PAGE_SHIFT;

				if(vm_add_region(as, region) < 0)
				{
					spin_unlock(&as->vm_spl);
					return -ENOMEM;
				}
			
				if(!is_mapping_shared(region) && !vmo_is_shared(region->vmo))
				{
					vmo_truncate_beginning_and_resize(to_shave_off, region->vmo);
					vmo_sanity_check(region->vmo);
				}
			}
			else
			{
				vm_remove_region(as, region);
				vm_region_destroy(region);
			}
		}
		else if(region->base < addr)
		{
			unsigned long offset = addr - region->base;
			unsigned long remainder = region_size - offset;
			to_shave_off = size < remainder ? size : remainder;

			if(to_shave_off != remainder)
			{
				unsigned long second_region_start = addr + to_shave_off;
				unsigned long second_region_size = remainder - to_shave_off;

				struct vm_region *new_region = vm_reserve_region(as,
						second_region_start,
						second_region_size);

				if(!new_region)
				{
					spin_unlock(&as->vm_spl);
					return -ENOMEM;
				}

				new_region->rwx = region->rwx;
				
				if(region->fd)
				{
					fd_get(region->fd);
					new_region->fd = region->fd;
				}

				new_region->mapping_type = region->mapping_type;
				new_region->offset = offset + to_shave_off;
				new_region->mm = region->mm;
				new_region->flags = region->flags;

				vm_remove_region(as, region);

				if(!is_mapping_shared(region) && !vmo_is_shared(region->vmo))
				{
					struct vm_object *second = vmo_split(offset, to_shave_off,
									     region->vmo);
					if(!second)
					{
						vm_remove_region(as, new_region);
						/* TODO: Undo new_region stuff and free it */
						spin_unlock(&as->vm_spl);
						return -ENOMEM;
					}

					if(as != &kernel_address_space)
						add_vmo_to_private_list(as, second);

					new_region->vmo = second;
					/* We should need to do this */
					new_region->offset = 0;
				}
				else
				{
					vmo_assign_mapping(region->vmo, new_region);
				
					vmo_ref(region->vmo);
					new_region->vmo = region->vmo;
/*
					if(new_region->mapping_type == MAP_SHARED && new_region->fd &&
						inode_requires_wb(new_region->fd->vfs_node))
					{
						writeback_add_region(new_region);
					}*/
				}
				/* The original region's size is offset */
				region->pages = offset >> PAGE_SHIFT;

				vm_add_region(as, region);
	
			}
			else
			{
				if(!is_mapping_shared(region) && !vmo_is_shared(region->vmo))
					vmo_resize(region_size - to_shave_off, region->vmo);
				region->pages -= to_shave_off >> PAGE_SHIFT;
			}
		}

		decrement_vm_stat(as, virtual_memory_size, to_shave_off);
		if(is_shared && !(region->flags & VM_USING_MAP_SHARED_OPT))
			decrement_vm_stat(as, shared_set_size, to_shave_off);
		
		addr += to_shave_off;
		size -= to_shave_off;
	}

	spin_unlock(&as->vm_spl);

	return 0;
}

static bool for_every_region_visit(const void *key, void *region, void *caller_data)
{
	bool (*func)(struct vm_region *) = (bool(*) (struct vm_region *)) caller_data;
	return func((struct vm_region *) region);
}

void vm_for_every_region(struct mm_address_space *as, bool (*func)(struct vm_region *region))
{
	rb_tree_traverse(as->area_tree, for_every_region_visit, (void *) func);
}

void vm_do_shootdown(struct tlb_shootdown *inv_data)
{
	paging_invalidate((void *) inv_data->addr, inv_data->pages);
}

extern struct spinlock scheduler_lock;

void __vm_invalidate_range(unsigned long addr, size_t pages, struct mm_address_space *mm)
{
	/* If the address > higher half, then we don't need to worry about
	 * stale tlb entries since no attacker can read kernel memory.
	*/
	if(is_higher_half((void *) addr))
	{
		paging_invalidate((void *) addr, pages);
		return;
	}

	struct process *p = get_current_process();

	for(unsigned int cpu = 0; cpu < get_nr_cpus(); cpu++)
	{
		if(cpu == get_cpu_nr())
		{
			if(p && get_current_address_space() == mm)
				paging_invalidate((void *) addr, pages);
		}
		else
		{
			/* Lock the scheduler so we don't get a race condition */
			struct spinlock *l = get_per_cpu_ptr_any(scheduler_lock, cpu);
			spin_lock(l);
			struct process *p = get_thread_for_cpu(cpu)->owner;

			if(!p || mm != &p->address_space)
			{
				spin_unlock(l);
				continue;
			}
	
			struct tlb_shootdown shootdown;
			shootdown.addr = addr;
			shootdown.pages = pages;
			cpu_send_message(cpu, CPU_FLUSH_TLB, &shootdown, true);

			spin_unlock(l);
		}
	}
}


void vm_invalidate_range(unsigned long addr, size_t pages)
{
	if(is_higher_half((void *) addr))
	{
		paging_invalidate((void *) addr, pages);
		return;
	}

	return __vm_invalidate_range(addr, pages, get_current_address_space());
}

bool vm_can_expand(struct mm_address_space *as, struct vm_region *region, size_t new_size)
{
	/* Can always shrink the mapping */
	if(new_size < region->pages << PAGE_SHIFT)
		return true;
	struct rb_itor it;
	it.node = NULL;
	it.tree = as->area_tree;

	assert(rb_itor_search(&it, (const void *) region->base) != false);

	/* If there's no region whose address > region->base, we know we can expand freely */
	bool node_valid = rb_itor_next(&it);
	if(!node_valid)
		return true;
	
	struct vm_region *second_region = *rb_itor_datum(&it);
	/* Calculate the hole size, and if >= new_size, we're good */
	size_t hole_size = second_region->base - region->base;

	if(hole_size >= new_size)
		return true;
	
	return false;
}

void __vm_expand_mapping(struct vm_region *region, size_t new_size)
{
	region->pages = new_size >> PAGE_SHIFT;
	vmo_resize(new_size, region->vmo);
}

int vm_expand_mapping(struct mm_address_space *as, struct vm_region *region, size_t new_size)
{
	MUST_HOLD_LOCK(&as->vm_spl);

	if(!vm_can_expand(as, region, new_size))
	{
		return -1;
	}

	__vm_expand_mapping(region, new_size);

	return 0;
}

int vm_expand_brk(size_t nr_pages)
{
	struct process *p = get_current_process();
	struct vm_region *brk_region = vm_find_region(p->address_space.brk);
	assert(brk_region != NULL);
	size_t new_size = (brk_region->pages + nr_pages) << PAGE_SHIFT; 

	return vm_expand_mapping(&p->address_space, brk_region, new_size);
}

int mremap_check_for_overlap(void *__old_address, size_t old_size, void *__new_address, size_t new_size)
{
	unsigned long old_address = (unsigned long) __old_address;
	unsigned long new_address = (unsigned long) __new_address;

	/* Written at 03:00, but the logic looks good? */
	if(old_address <= (unsigned long) new_address
			&& old_address + old_size > (unsigned long) new_address)
		return -1;
	if(old_address <= (unsigned long) new_address + new_size
			&& old_address + old_size > (unsigned long) new_address + new_size)
		return -1;
	return 0;
}

void *vm_remap_create_new_mapping_of_shared_pages(void *new_address, size_t new_size,
	int flags, void *old_address)
{
	struct process *current = get_current_process();
	void *ret = MAP_FAILED;
	bool fixed = flags & MREMAP_FIXED;
	struct vm_region *new_mapping = NULL;

	
	struct vm_region *old_region = vm_find_region(old_address);
	if(!old_region)
	{
		ret = (void *) -EFAULT;
		goto out;
	}

	if(old_region->mapping_type != MAP_SHARED)
	{
		ret = (void *) -EINVAL;
		goto out;
	}

	if(fixed)
	{
		if(vm_sanitize_address(new_address, new_size >> PAGE_SHIFT) < 0)
		{
			ret = (void *) -EINVAL;
			goto out;
		}

		if(mremap_check_for_overlap(old_address, new_size, new_address, new_size) < 0)
		{
			ret = (void *) -EINVAL;
			goto out;
		}

		new_mapping = vm_reserve_address(new_address, new_size >> PAGE_SHIFT,
			VM_TYPE_REGULAR, old_region->rwx);
	}
	else
	{
		new_mapping = vm_allocate_region(&current->address_space,
						 (unsigned long) current->address_space.mmap_base,
						 new_size);
		if(new_mapping)
		{
			new_mapping->type = VM_TYPE_REGULAR;
			new_mapping->rwx = old_region->rwx;
		}
	}

	if(!new_mapping)
	{
		ret = (void *) -ENOMEM;
		goto out;
	}

	vm_copy_region(old_region, new_mapping);
	ret = (void *) new_mapping->base;
out:
	spin_unlock(&current->address_space.vm_spl);
	return ret;
}

void *vm_try_move(struct vm_region *old_region, unsigned long new_base, size_t new_size)
{
	struct process *current = get_current_process();
	
	vm_remove_region(&current->address_space, old_region);

	old_region->base = new_base;
	__vm_expand_mapping(old_region, new_size);
	/* TODO: What to do in case of a failure? */
	vm_add_region(&current->address_space, old_region);
	
	/* TODO: Maybe unmapping isn't the best option on a move and we should copy mappings */
	__vm_unmap_range((void *) old_region->base, old_region->pages);

	vm_print_umap();
	return (void *) old_region->base;
}

void *vm_remap_try(void *old_address, size_t old_size, void *new_address, size_t new_size, int flags)
{
	size_t n;
	struct process *current = get_current_process();
	struct vm_region *reg = vm_find_region(old_address);
	if(!reg)
		return (void *) -EFAULT;

	struct vm_region *old_reg = vm_split_region(&current->address_space, reg,
						    (unsigned long) old_address, old_size, &n);
	if(!old_reg)
		return (void *) -ENOMEM;

	if(vm_expand_mapping(&current->address_space, old_reg, new_size) < 0)
	{
		if(flags & MREMAP_MAYMOVE)
		{
			unsigned long new_base = vm_allocate_base(&current->address_space,
						  (unsigned long) current->address_space.mmap_base, new_size);
			return vm_try_move(old_reg, new_base, new_size);
		}

		return (void *) -ENOMEM;
	}

	return (void *) old_reg->base;
}

void vm_unmap_every_region_in_range(struct mm_address_space *as, unsigned long start,
				    unsigned long length)
{
	unsigned long limit = start + length;
	while(true)
	{
		void **pp = rb_tree_search_ge(as->area_tree, (void *) start);
		if(!pp)
			return;

		struct vm_region *reg = *pp;
		if(reg->base >= start + length)
			return;
		unsigned long reg_len = reg->pages << PAGE_SHIFT;
		unsigned long to_unmap = limit - reg->base < reg_len
			? limit - reg->base : reg_len;
		vm_munmap(as, (void *) reg->base, to_unmap);
	}
}

/* TODO: Test things */
void *sys_mremap(void *old_address, size_t old_size, size_t new_size, int flags, void *new_address)
{
	/* Check http://man7.org/linux/man-pages/man2/mremap.2.html for documentation */
	struct process *current = get_current_process();
	bool may_move = flags & MREMAP_MAYMOVE;
	bool fixed = flags & MREMAP_FIXED;
	bool wants_create_new_mapping_of_pages = old_size == 0 && may_move;
	void *ret = MAP_FAILED;
	spin_lock(&current->address_space.vm_spl);

	/* TODO: Unsure on what to do if new_size > old_size */
	
	if(vm_sanitize_address(old_address, old_size >> PAGE_SHIFT) < 0)
	{
		ret = (void *) -EFAULT;
		goto out;
	}

	if(wants_create_new_mapping_of_pages)
		return vm_remap_create_new_mapping_of_shared_pages(new_address, new_size, flags, old_address);

	if(old_size == 0)
	{
		ret = (void *) -EINVAL;
		goto out;
	}

	if(new_size == 0)
	{
		ret = (void *) -EINVAL;
		goto out;
	}

	if(!fixed)
	{
		ret = vm_remap_try(old_address, old_size, new_address, new_size, flags);
		goto out;
	}
	else
	{

		if(vm_sanitize_address(new_address, new_size >> PAGE_SHIFT) < 0)
		{
			ret = (void *) -EINVAL;
			goto out;
		}

		if(mremap_check_for_overlap(old_address, old_size, new_address, new_size) < 0)
		{
			ret = (void *) -EINVAL;
			goto out;
		}

		struct vm_region *reg = vm_find_region(old_address);
		if(!reg)
		{
			ret = (void *) -EFAULT;
			goto out;
		}
		size_t n;

		struct vm_region *old_reg = vm_split_region(&current->address_space, reg,
							    (unsigned long) old_address, old_size, &n);
		if(!old_reg)
		{
			ret = (void *) -ENOMEM;
			goto out;
		}

		vm_unmap_every_region_in_range(&current->address_space,
					       (unsigned long) new_address,
					       new_size);

		ret = vm_try_move(old_reg, (unsigned long) new_address, new_size);
	}


out:
	spin_unlock(&current->address_space.vm_spl);
	return ret;
}

struct page *vm_commit_page(void *page)
{
	struct vm_region *reg = vm_find_region(page);
	if(!reg)
	{
		return NULL;
	}
	
	if(!reg->vmo)
		return NULL;

	struct vm_object *vmo = reg->vmo;

	unsigned long off = reg->offset + ((unsigned long) page - reg->base);
	struct page *p = vmo_get(vmo, off, true);
	if(!p)
		return NULL;
	if(!map_pages_to_vaddr(page, page_to_phys(p), PAGE_SIZE, reg->rwx))
		return NULL;
	return p;
}

int vm_change_locks_range_in_region(struct vm_region *region,
	unsigned long addr, unsigned long len, unsigned long flags)
{
	assert(region->vmo != NULL);

	spin_lock(&region->vmo->page_lock);

	struct rb_itor it;
	it.node = NULL;
	it.tree = region->mm->area_tree;
	unsigned long starting_off = region->offset + (addr - region->base); 
	unsigned long end_off = starting_off + len;
	bool node_valid = rb_itor_search_ge(&it, (void *) starting_off);

	while(node_valid)
	{
		struct page *p = *rb_itor_datum(&it);
		if(p->off >= end_off)
			return 0;
		if(flags & VM_LOCK)
			p->flags |= PAGE_FLAG_LOCKED;
		else
			p->flags &= ~(PAGE_FLAG_LOCKED);

		node_valid = rb_itor_next(&it);
	}

	spin_unlock(&region->vmo->page_lock);
	return 0;
}

int vm_change_region_locks(void *__start, unsigned long length, unsigned long flags)
{
	/* We don't need to do this with kernel addresses */

	if(is_higher_half(__start))
		return 0;

	struct mm_address_space *as = &get_current_process()->address_space;

	unsigned long limit = (unsigned long) __start + length;
	unsigned long addr = (unsigned long) __start;

	spin_lock(&as->vm_spl);

	while(addr < limit)
	{
		struct vm_region *region = vm_find_region((void *) addr);
		if(!region)
		{
			spin_unlock(&as->vm_spl);
			return errno = ENOENT, -1;
		}

		size_t len = min(length, region->pages << PAGE_SHIFT);
		if(vm_change_locks_range_in_region(region, addr, len, flags) < 0)
		{
			spin_unlock(&as->vm_spl);
			return -1;
		}

		if(flags & VM_FUTURE_PAGES)
		{
			if(flags & VM_LOCK)
				region->vmo->flags |= VMO_FLAG_LOCK_FUTURE_PAGES;
			else
				region->vmo->flags &= ~VMO_FLAG_LOCK_FUTURE_PAGES;
		}
	
		addr += len;
		length -= len;
	}

	spin_unlock(&as->vm_spl);
	return 0;
}

int vm_lock_range(void *start, unsigned long length, unsigned long flags)
{
	return vm_change_region_locks(start, length, flags | VM_LOCK);
}

int vm_unlock_range(void *start, unsigned long length, unsigned long flags)
{
	return vm_change_region_locks(start, length, flags);
}

void vm_wp_page(struct mm_address_space *mm, void *vaddr)
{
	printk("wp page %p %p\n", mm, vaddr);
	assert(paging_write_protect(vaddr, mm) == true);

	__vm_invalidate_range((unsigned long) vaddr, 1, mm);
}

void vm_wp_page_for_every_region(struct page *page, struct vm_object *vmo)
{
	size_t page_off = page->off;

	spin_lock(&vmo->mapping_lock);

	list_for_every(&vmo->mappings)
	{
		struct vm_region *region = container_of(l, struct vm_region, vmo_head);
		spin_lock(&region->mm->vm_spl);
		size_t mapping_off = (size_t) region->offset;
		size_t mapping_size = region->pages << PAGE_SHIFT;


		if(page_off >= mapping_off && mapping_off + mapping_size > page_off)
		{
			/* The page is included in this mapping, so WP it */
			unsigned long vaddr = region->base + (page_off - mapping_off);
			vm_wp_page(region->mm, (void *) vaddr);
		}

		spin_unlock(&region->mm->vm_spl);
	}

	spin_unlock(&vmo->mapping_lock);
}