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
#include <onyx/copy.h>

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

int vm_region_setup_backing(struct vm_region *region, size_t pages, bool is_file_backed);
int populate_shared_mapping(void *page, struct file *fd,
	struct vm_region *entry, size_t nr_pages);
void vm_remove_region(struct mm_address_space *as, struct vm_region *region);
int vm_add_region(struct mm_address_space *as, struct vm_region *region);
void remove_vmo_from_private_list(struct mm_address_space *mm, struct vm_object *vmo);
void add_vmo_to_private_list(struct mm_address_space *mm, struct vm_object *vmo);
bool vm_using_shared_optimization(struct vm_region *region);
int __vm_munmap(struct mm_address_space *as, void *__addr, size_t size);
void vm_unmap_every_region_in_range(struct mm_address_space *as, unsigned long start,
				    unsigned long length);
bool limits_are_contained(struct vm_region *reg, unsigned long start, unsigned long limit);

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
	MUST_HOLD_LOCK(&as->vm_spl);

	struct vm_region *region = zalloc(sizeof(struct vm_region));
	if(!region)
		return NULL;

	region->base = start;
	region->pages = vm_size_to_pages(size);
	region->rwx = 0;

	dict_insert_result res = rb_tree_insert(as->area_tree,
						(void *) start);

	if(res.inserted == false)
	{
		if(res.datum_ptr)
		{
			spin_unlock(&as->vm_spl);
			printk("Oopsie at %lx\n", start);

			vm_print_umap();
			panic("oops");
		}

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
	MUST_HOLD_LOCK(&as->vm_spl);

	if(min < as->start)
		min = as->start;

	struct rb_itor it;
	it.node = NULL;
	it.tree = as->area_tree;
	bool node_valid;
	unsigned long last_end = min;
	struct vm_region *f = NULL;

	if(min != as->start)
		node_valid = rb_itor_search_ge(&it, (const void *) min);
	else
	{
		node_valid = rb_itor_first(&it);
	}

	if(!node_valid)
		goto done;
	

	/* Check if there's a gap between the first node
	 * and the start of the address space
	*/

	f = (struct vm_region *) *rb_itor_datum(&it);

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
		struct vm_region *f = (struct vm_region *) *rb_itor_datum(&it);
		last_end = f->base + (f->pages << PAGE_SHIFT);

		node_valid = rb_itor_next(&it);
		if(!node_valid)
			break;

		struct vm_region *vm = (struct vm_region *) *rb_itor_datum(&it);

		if(vm->base - last_end >= size && min <= vm->base)
			break;
	}

done:
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
	vm_save_current_mmu(&kernel_address_space);

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
	spin_lock(&kernel_address_space.vm_spl);

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

	spin_unlock(&kernel_address_space.vm_spl);

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
		size_t poff = (size_t) rb_itor_key(&it);
		
		if(poff >= off + (nr_pages << PAGE_SHIFT))
			break;
		unsigned long reg_off = poff - off;
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
		inode_requires_wb(reg->fd->f_ino);
}

bool vm_mapping_is_anon(struct vm_region *reg)
{
	return reg->fd == NULL && reg->vmo->type == VMO_ANON;
}

bool vm_mapping_requires_write_protect(struct vm_region *reg)
{
	if(vm_mapping_requires_wb(reg))
	{
		return true;
	}

	return false;
}

void vm_region_destroy(struct vm_region *region)
{
	/* First, unref things */
	if(region->fd)
	{
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

struct vm_region *__vm_allocate_virt_region(uint64_t flags, size_t pages, uint32_t type, uint64_t prot)
{
	bool allocating_kernel = true;
	if(flags & VM_ADDRESS_USER)
		allocating_kernel = false;

	struct mm_address_space *as = allocating_kernel ? &kernel_address_space :
		&get_current_process()->address_space;

	MUST_HOLD_LOCK(&as->vm_spl);

	unsigned long base_addr = vm_get_base_address(flags, type);

	struct vm_region *region = vm_allocate_region(as, base_addr, pages << PAGE_SHIFT);

	if(region)
	{
		region->rwx = prot;
		region->type = type;
	}

	return region;
}

struct vm_region *vm_allocate_virt_region(uint64_t flags, size_t pages, uint32_t type, uint64_t prot)
{
	if(pages == 0)
		return NULL;

	/* Lock everything before allocating anything */
	bool allocating_kernel = true;
	if(flags & VM_ADDRESS_USER)
		allocating_kernel = false;

	__vm_lock(allocating_kernel);

	struct vm_region *region = __vm_allocate_virt_region(flags, pages, type, prot);

	__vm_unlock(allocating_kernel);

	return region;
}

bool vm_region_is_empty(void *addr, size_t length)
{
	struct mm_address_space *mm = get_current_address_space();
	struct rb_itor it;
	it.tree = mm->area_tree;
	it.node = NULL;
	unsigned long limit = (unsigned long) addr + length;

	bool node_valid = rb_itor_first(&it);
	
	while(node_valid)
	{
		struct vm_region *reg = *rb_itor_datum(&it);

		if(limits_are_contained(reg, (unsigned long) addr, limit))
		{
			return false;
		}

		node_valid = rb_itor_next(&it);
	}
	
	return true;
}

#define VM_CREATE_REGION_AT_DEBUG			0

struct vm_region *__vm_create_region_at(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	bool reserving_kernel = is_higher_half(addr);
	struct vm_region *v = NULL;

	if(!vm_region_is_empty(addr, pages << PAGE_SHIFT))
	{
#if VM_CREATE_REGION_AT_DEBUG
		sched_enable_preempt();
		printk("Failed to map %p - %lx\n", addr, (unsigned long) addr + (pages << PAGE_SHIFT));
		vm_print_umap();
		sched_disable_preempt();
#endif

		errno = EINVAL;
		return NULL;
	}

	struct mm_address_space *mm = &get_current_process()->address_space;

	if(reserving_kernel)
		v = vm_reserve_region(&kernel_address_space, (unsigned long) addr, pages * PAGE_SIZE);
	else
		v = vm_reserve_region(mm, (unsigned long) addr, pages * PAGE_SIZE);
	if(!v)
	{
		addr = NULL;
		errno = ENOMEM;
		goto return_;
	}

	v->base = (unsigned long) addr;
	v->pages = pages;
	v->type = type;
	v->rwx = prot;

return_:
	return v;
}

struct vm_region *vm_create_region_at(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	bool reserving_kernel = is_higher_half(addr);
	struct vm_region *v = NULL;

	__vm_lock(reserving_kernel);

	assert(prot & VM_USER && !reserving_kernel);
	v = __vm_create_region_at(addr, pages, type, prot);

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

int vm_flush_mapping(struct vm_region *mapping, struct process *proc, unsigned int flags,
                     unsigned int rwx)
{
	struct vm_object *vmo = mapping->vmo;
	
	assert(vmo != NULL);

	size_t nr_pages = mapping->pages;

	size_t off = mapping->offset;
	struct rb_itor it;
	it.node = NULL;

	spin_lock(&vmo->page_lock);

	it.tree = vmo->pages;
	int mapping_rwx = flags & VM_FLUSH_RWX_VALID ? (int) rwx : mapping->rwx; 

	bool node_valid = rb_itor_search_ge(&it, (void *) off);
	while(node_valid)
	{
		struct page *p = *rb_itor_datum(&it);
		size_t poff = (size_t) rb_itor_key(&it);

		if(poff >= off + (nr_pages << PAGE_SHIFT))
			break;
		unsigned long reg_off = poff - off;
		if(!__map_pages_to_vaddr(proc, (void *) (mapping->base + reg_off), page_to_phys(p),
			PAGE_SIZE, mapping_rwx))
		{
			spin_unlock(&vmo->page_lock);
			return -1;
		}

		node_valid = rb_itor_next(&it);
	}

	spin_unlock(&vmo->page_lock);
	return 0;
}

int vm_flush(struct vm_region *entry, unsigned int flags, unsigned int rwx)
{
	struct process *p = entry->mm ? entry->mm->process : NULL;
#if DEBUG_VM_FLUSH
printk("Has process? %s\n", p ? "true" : "false");
#endif
	return vm_flush_mapping(entry, p, flags, rwx);
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

	if(needs_to_fork_memory)
	{
		/* No need to ref the vmo since it was a new vmo created for us while forking. */
		new_region->vmo = find_forked_private_vmo(new_region->vmo, it->target_mm);
		assert(new_region->vmo != NULL);
		vmo_assign_mapping(new_region->vmo, new_region);
	}
	else
	{
		vmo_ref(new_region->vmo);
		vmo_assign_mapping(new_region->vmo, new_region);
	}

	if(vmo_failure)
	{
		dict_remove_result res = rb_tree_remove(it->target_mm->area_tree, key);
		assert(res.removed == true);
		free(new_region);
		goto ohno;
	}

	new_region->mm = it->target_mm;

	/* If it's a private mapping, we're mapping it either COW if it's a writable mapping, or
	 * just not writable if it's a a RO/R-X mapping. Therefore, we mask the VM_WRITE bit
	 * out of the flush permissions, as to map things write-protected if it's a writable mapping.
	 */

	unsigned int new_rwx = is_private ? new_region->rwx & ~VM_WRITE : new_region->rwx;
	if(vm_flush(new_region, VM_FLUSH_RWX_VALID, new_rwx) < 0)
	{
		/* Let the generic addr space destruction code handle this, 
		 * since there's everything's set now */
		goto ohno;
	}

	if(is_private && region->rwx & VM_WRITE)
	{
		/* If the region is writable and we're a private mapping, we'll need to
		 * mark the original mapping as write-protected too, so the parent can also trigger COW behaviour.
		 */
		int st = vm_flush(region, VM_FLUSH_RWX_VALID, new_rwx);

		/* I don't even know how it should be possible to OOM changing protections
		 * of mappings that already exist. TODO: BUT, is it a plausible thing and should we handle it? */
		assert(st == 0);
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
	addr_space->mmap_base = current_mm->mmap_base;
	addr_space->brk = current_mm->brk;
	addr_space->start = current_mm->start;
	addr_space->end = current_mm->end;

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
	struct vm_region *vm = vm_allocate_virt_region(VM_KERNEL, pages, type, perms);
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

	if(vm_flush(vm, 0, 0) < 0)
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

void *vm_mmap(void *addr, size_t length, int prot, int flags, struct file *file, off_t off)
{
	int st = 0;
	struct vm_region *area = NULL;
	bool is_file_mapping = file != NULL;

	struct mm_address_space *mm = get_current_address_space();

	/* We don't like this offset. */
	if(off & (PAGE_SIZE - 1))
		return (void *) (unsigned long) -EINVAL;

	spin_lock(&mm->vm_spl);

	/* Calculate the pages needed for the overall size */
	size_t pages = vm_size_to_pages(length);

	/* TODO: Add PROT_NONE support */
	int vm_prot = VM_USER |
		      ((prot & PROT_WRITE) ? VM_WRITE : 0) |
		      ((!(prot & PROT_EXEC)) ? VM_NOEXEC : 0);

	if(is_higher_half(addr)) /* User addresses can't be on the kernel's address space */
	{
		if(flags & MAP_FIXED)
		{
			st = -ENOMEM;
			goto out_error;
		}
		else
			addr = NULL;
	}


	if(!addr)
	{
		if(flags & MAP_FIXED)
		{
			st = -ENOMEM;
			goto out_error;
		}
		/* Specified by POSIX, if addr == NULL, guess an address */
		area = __vm_allocate_virt_region(VM_ADDRESS_USER, pages,
			VM_TYPE_SHARED, vm_prot);
	}
	else
	{
		if(flags & MAP_FIXED)
		{
			struct mm_address_space *mm = &get_current_process()->address_space;
			vm_unmap_every_region_in_range(mm, (unsigned long) addr, pages << PAGE_SHIFT);
		}

		area = __vm_create_region_at(addr, pages, VM_TYPE_REGULAR, vm_prot);
		if(!area)
		{
			if(flags & MAP_FIXED)
			{
				st = -ENOMEM;
				goto out_error;
			}

			area = __vm_allocate_virt_region(VM_ADDRESS_USER, pages, VM_TYPE_REGULAR, vm_prot);
		}
	}

	if(!area)
	{
		st = -ENOMEM;
		goto out_error;
	}

	if(flags & MAP_SHARED)
		area->mapping_type = MAP_SHARED;
	else
		area->mapping_type = MAP_PRIVATE;

	if(is_file_mapping)
	{
		//printk("Mapping off %lx, size %lx, prots %x\n", off, length, prot);

		/* Set additional meta-data */

		area->type = VM_TYPE_FILE_BACKED;

		area->offset = off;
		area->fd = file;
		fd_get(file);

		struct inode *ino = file->f_ino;

		if((ino->i_type == VFS_TYPE_BLOCK_DEVICE 
		   || ino->i_type == VFS_TYPE_CHAR_DEVICE)
		   && area->mapping_type == MAP_SHARED)
		{
			if(!ino->i_fops->mmap)
			{
				return (void *) -ENOSYS;
			}

			void *ret = ino->i_fops->mmap(area, file);

			spin_unlock(&mm->vm_spl);

			return ret;
		}
	}

	if(vm_region_setup_backing(area, pages, !(flags & MAP_ANONYMOUS)) < 0)
	{
		vm_munmap(mm, addr, pages << PAGE_SHIFT);
		return (void *) -ENOMEM;
	}

	void *base = (void *) area->base;

	spin_unlock(&mm->vm_spl);
	return base;

out_error:
	spin_unlock(&mm->vm_spl);
	return (void *) (unsigned long) st;
}

void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t off)
{
	int error = 0;

	struct file *file = NULL;
	bool is_file_mapping = !(flags & MAP_ANONYMOUS);

	/* Ok, start the basic input sanitation for user-space inputs */
	if(length == 0)
		return (void*) -EINVAL;

	if(!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
		return (void*) -EINVAL;

	if(flags & MAP_PRIVATE && flags & MAP_SHARED)
		return (void*) -EINVAL;

	/* Our mmap() implementation needs page aligned offsets */
	if(off % PAGE_SIZE)
		return (void*) -EINVAL;

	if(is_file_mapping) /* This is a file-backed mapping */
	{
		file = get_file_description(fd);
		if(!file)
			return (void *) (unsigned long) -errno;

		bool fd_has_write = !(file->f_flags & O_WRONLY) &&
				    !(file->f_flags & O_RDWR);
	
		if(fd_has_write && prot & PROT_WRITE && flags & MAP_SHARED)
		{
			/* You can't map for writing on a file without read access with MAP_SHARED! */
			error = -EACCES;
			goto out_error;
		}
	}

	return vm_mmap(addr, length, prot, flags, file, off);

out_error:
	if(file)	fd_put(file);
	return (void *) (unsigned long) error;
}


int sys_munmap(void *addr, size_t length)
{
	if(is_higher_half(addr))
		return -EINVAL;

	size_t pages = vm_size_to_pages(length);
	
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
		/*struct file *ino = dest->fd->f_ino;
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

	size_t pages = vm_size_to_pages(len);

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

	printk("(key %p) [%016lx - %016lx] : %s%s%s\n", key, region->base,
					       region->base + (region->pages << PAGE_SHIFT),
					       "R", w ? "W" : "-", x ? "X" : "-");
	printk("vmo %p mapped at offset %lx", region->vmo, region->offset);
	if(file_backed)
		printk(" - file backed ino %lu\n", fd->f_ino->i_inode);
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
	size_t pages = vm_size_to_pages(size);
	
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

	vm_invalidate_range((unsigned long) virt, pages);

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

	size_t pages = vm_size_to_pages(size);
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

	entry->flags = 

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
	/* Page permissions - is prefilled by calling code */
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
	ctx->page = vmo_get(entry->vmo, vmo_off, VMO_GET_MAY_POPULATE);

	return ctx->page;
}

int vm_handle_non_present_wp(struct fault_info *info, struct vm_pf_context *ctx)
{
	struct vm_region *entry = ctx->entry;

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
			/* This is done in vm_pf_get_page_from_vmo */
		}
	}

	return 0;
}

bool vm_mapping_is_cow(struct vm_region *entry)
{
	return entry->mapping_type == MAP_PRIVATE;
}

int vm_handle_non_present_copy_on_write(struct fault_info *info, struct vm_pf_context *ctx)
{
	bool is_write = info->write;

	/* Let the vm_pf_get_page_from_vmo() do that */
	if(is_write)
		return 0;
	
	struct vm_region *entry = ctx->entry;
	size_t vmo_off = (ctx->vpage - entry->base) + entry->offset;

	struct vm_object *vmo = entry->vmo;

	/* If we don't have a COW clone, this means we're an anon mapping and we're just looking to COW-map
	 * the zero page
	 */
	if(!vmo->cow_clone)
	{
		page_ref(vm_zero_page);
		vmo_add_page(vmo_off, vm_zero_page, vmo);
		ctx->page = vm_zero_page;
		ctx->page_rwx &= ~VM_WRITE;
		return 0;
	}

#if 0
	printk("Vmo off: %lx\n", vmo_off);
	printk("Faulting %lx in\n", ctx->vpage);
#endif

	struct page *page = vmo_get_cow_page(vmo, vmo_off);
	if(!page)
		return -1;

	ctx->page = page;
	ctx->page_rwx &= ~VM_WRITE;

	return 0;
}

int vm_handle_non_present_pf(struct vm_pf_context *ctx)
{
	struct vm_region *entry = ctx->entry;
	struct fault_info *info = ctx->info;

	if(vm_mapping_requires_write_protect(entry))
	{
		if(vm_handle_non_present_wp(info, ctx) < 0)
			return -1;
	}
	else if(vm_mapping_is_cow(entry))
	{
		if(vm_handle_non_present_copy_on_write(info, ctx) < 0)
			return -1;
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
		page_unpin(ctx->page);
		info->error = VM_SIGSEGV;
		return -1;
	}

	page_unpin(ctx->page);

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

int vm_handle_present_cow(struct vm_pf_context *ctx)
{
	struct vm_object *vmo = ctx->entry->vmo;
	struct fault_info *info = ctx->info;

	struct vm_region *entry = ctx->entry;
	size_t vmo_off = (ctx->vpage - entry->base) + entry->offset;

	struct page *new_page = vmo_cow_on_page(vmo, vmo_off);
	if(!new_page)
	{
		info->error = VM_SIGSEGV;
		return -1;
	}

	if(!map_pages_to_vaddr((void *) ctx->vpage,
				page_to_phys(new_page), PAGE_SIZE, ctx->page_rwx))
	{
		page_unpin(new_page);
		info->error = VM_SIGSEGV;
		return -1;
	}

	page_unpin(new_page);

	return 0;
}

int vm_handle_present_pf(struct vm_pf_context *ctx)
{
	struct vm_region *entry = ctx->entry;
	struct fault_info *info = ctx->info;

	if(info->write & !(ctx->mapping_info & PAGE_WRITABLE))
	{
		if(vm_mapping_requires_wb(entry))
			vm_handle_write_wb(ctx);
		else if(vm_mapping_is_cow(entry))
		{
			//printk("C O W'ing page %lx, file backed: %s, pid %d\n", ctx->vpage, entry->fd ? "yes" : "no", get_current_process()->pid);
			if(vm_handle_present_cow(ctx) < 0)
				return -1;
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
	bool use_kernel_as = !info->user && is_higher_half((void *) info->fault_address);
	struct mm_address_space *as = use_kernel_as ? &kernel_address_space
		: get_current_address_space();

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

	/*if(entry->pages == 3)
	{
		printk("Ip: %lx\n", info->ip - (unsigned long) get_current_process()->image_base);
	}*/


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
	bool free_pgd = true;

	/* First, iterate through the rb tree and free/unmap stuff */
	spin_lock(&mm->vm_spl);
	rb_tree_free(mm->area_tree, vm_destroy_area);

	/* We're going to swap our address space to init's, and free our own */
	
	void *own_addrspace = vm_get_pgd(&current->address_space.arch_mmu);

	if(own_addrspace == vm_get_fallback_cr3())
	{
		/* If init is deciding to exec without forking, don't free the fallback pgd! */
		free_pgd = false;
	}

	struct arch_mm_address_space old_arch_mmu;
	vm_set_pgd(&old_arch_mmu, own_addrspace);

	vm_set_pgd(&current->address_space.arch_mmu, vm_get_fallback_cr3());

	vm_load_arch_mmu(&current->address_space.arch_mmu);

	if(free_pgd)
		vm_free_arch_mmu(&old_arch_mmu);

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
	if(off == 1)
		return 0;

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

static struct sysfs_object vm_obj;
static struct sysfs_object aslr_control;
static struct sysfs_object kmaps;

void vm_sysfs_init(void)
{
	INFO("vmm", "Setting up /sys/vm\n");

	assert(sysfs_object_init("vm", &vm_obj) == 0);
	vm_obj.perms = 0644 | S_IFDIR;

	assert(sysfs_init_and_add("aslr_ctl", &aslr_control, &vm_obj) == 0);
	aslr_control.read = aslr_read;
	aslr_control.write = aslr_write;
	aslr_control.perms = 0644 | S_IFREG;

	assert(sysfs_init_and_add("kmaps", &kmaps, &vm_obj) == 0);
	kmaps.read = kmaps_read;
	kmaps.perms = 0444 | S_IFREG;

	sysfs_add(&vm_obj, NULL);
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

		siginfo_t sinfo = {};
		sinfo.si_code = SI_KERNEL;
		sinfo.si_addr = (void *) info->fault_address;
		kernel_tkill(SIGSEGV, get_current_thread(), SIGNAL_FORCE, &sinfo);
	}
	else
		panic("Unable to satisfy paging request");
}

void *vm_map_vmo(size_t flags, uint32_t type, size_t pages, size_t prot, struct vm_object *vmo)
{
	bool kernel = !(flags & VM_ADDRESS_USER);
	void *ret = NULL;
	struct mm_address_space *mm = get_current_address_space();
	spin_lock(&mm->vm_spl);

	struct vm_region *reg = __vm_allocate_virt_region(flags, pages, type, prot);
	if(!reg)
	{
		goto ret;
	}

	vmo_ref(vmo);

	reg->vmo = vmo;
	vmo_assign_mapping(vmo, reg);
	reg->mapping_type = MAP_SHARED;

	if(kernel)
	{
		if(vmo_prefault(reg->vmo, pages << PAGE_SHIFT, 0) < 0)
		{
			__vm_munmap(&kernel_address_space, (void *) reg->base, pages << PAGE_SHIFT);
			goto ret;
		}

		if(vm_flush(reg, 0, 0) < 0)
		{
			__vm_munmap(&kernel_address_space, (void *) reg->base, pages << PAGE_SHIFT);
			goto ret;
		}

#ifdef CONFIG_KASAN
		kasan_alloc_shadow(reg->base, pages << PAGE_SHIFT, true);
#endif
	}

	ret = (void *) reg->base;
ret:
	spin_unlock(&mm->vm_spl);
	return ret;
}

void *get_pages(size_t flags, uint32_t type, size_t pages, size_t prot, uintptr_t alignment)
{
	bool kernel = !(flags & VM_ADDRESS_USER);

	struct vm_region *va = vm_allocate_virt_region(flags, pages, type, prot);
	if(!va)
		return NULL;
	
	if(vm_region_setup_backing(va, pages, false) < 0)
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

		if(vm_flush(va, 0, 0) < 0)
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
	unsigned long old = thread_change_addr_limit(VM_KERNEL_ADDR_LIMIT);
	assert(ino->i_fops->readpage != NULL);
	ssize_t read = ino->i_fops->readpage(p, off + file_off, ino);

	thread_change_addr_limit(old);

	if(read < 0)
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

bool vm_using_shared_optimization(struct vm_region *region)
{
	return region->flags & VM_USING_MAP_SHARED_OPT;
}

int vm_region_setup_backing(struct vm_region *region, size_t pages, bool is_file_backed)
{
	bool is_shared = is_mapping_shared(region);
	bool is_kernel = is_higher_half((void *) region->base);

	struct vm_object *vmo;

	if(is_file_backed && is_shared)
	{
		struct inode *ino = region->fd->f_ino;

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
	}
	else if(is_file_backed && !is_shared)
	{
		/* Alright, we're using COW to fault stuff in */
		/* store the offset in vmo->priv */
		vmo = vmo_create(pages * PAGE_SIZE, (void *) region->offset);
		if(!vmo)
			return -1;
		vmo->ino = region->fd->f_ino;
		vmo->commit = vm_commit_private;
		vmo_do_cow(vmo, region->fd->f_ino->i_pages);

		region->offset = 0;
	}
	else
	{
		vmo = vmo_create_phys(pages * PAGE_SIZE);

		if(!vmo)
			return -1;
		vmo->type = VMO_ANON;
	}

	vmo_assign_mapping(vmo, region);

	if(!is_shared && !is_kernel)
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
	return region->mapping_type == MAP_SHARED;
}

bool is_file_backed(struct vm_region *region)
{
	return region->type == VM_TYPE_FILE_BACKED;
}

void *map_user(void *addr, size_t pages, uint32_t type, uint64_t prot)
{
	struct vm_region *en = vm_create_region_at(addr, pages, type, prot);
	if(!en)
		return NULL;
	if(vm_region_setup_backing(en, pages, false) < 0)
		return NULL;
	return addr;
}

void *map_page_list(struct page *pl, size_t size, uint64_t prot)
{
	struct vm_region *entry = vm_allocate_virt_region(VM_KERNEL,
		vm_size_to_pages(size), VM_TYPE_REGULAR, prot);
	if(!entry)
		return NULL;
	void *vaddr = (void *) entry->base;

	uintptr_t u = (uintptr_t) vaddr;
	while(pl != NULL)
	{
		if(!map_pages_to_vaddr((void *) u, page_to_phys(pl), PAGE_SIZE, prot))
		{
			vm_destroy_mappings(vaddr, vm_size_to_pages(size));
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

int vm_create_address_space(struct mm_address_space *mm, struct process *process)
{
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
		return -ENOMEM;
	}

	return 0;
}

int vm_create_brk(struct mm_address_space *mm)
{
	mm->brk = vm_mmap(vm_gen_brk_base(), 1 << PAGE_SHIFT, PROT_WRITE,
                      MAP_PRIVATE | MAP_FIXED | MAP_ANON, NULL, 0);

	if(!mm->brk)
	{
		return -ENOMEM;
	}

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
	return vm_get_pgd(&kernel_address_space.arch_mmu);
}

void vm_remove_region(struct mm_address_space *as, struct vm_region *region)
{
	MUST_HOLD_LOCK(&as->vm_spl);

	dict_remove_result res = rb_tree_remove(as->area_tree,
						 (const void *) region->base);
	assert(res.removed == true);
}

int vm_add_region(struct mm_address_space *as, struct vm_region *region)
{
	MUST_HOLD_LOCK(&as->vm_spl);

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

int __vm_munmap(struct mm_address_space *as, void *__addr, size_t size)
{
	size = ALIGN_TO(size, PAGE_SIZE);
	unsigned long addr = (unsigned long) __addr;
	unsigned long limit = addr + size;

	MUST_HOLD_LOCK(&as->vm_spl);

	while(addr < limit)
	{
		struct vm_region *region = vm_find_region_in_tree((void *) addr, as->area_tree);
		if(!region)
		{
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
						inode_requires_wb(new_region->fd->f_ino))
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

	return 0;
}

int vm_munmap(struct mm_address_space *as, void *__addr, size_t size)
{
	spin_lock(&as->vm_spl);

	int ret = __vm_munmap(as, __addr, size);

	spin_unlock(&as->vm_spl);

	return ret;
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

			/* We need to save irqs here because there might be an IRQ that
			 * interrupts us and wants to wake a thread, and then we're deadlocked.
			 */
	
			spin_lock_irqsave(l);
			struct process *p = get_thread_for_cpu(cpu)->owner;

			if(!p || mm != &p->address_space)
			{
				spin_unlock_irqrestore(l);
				continue;
			}
	
			struct tlb_shootdown shootdown;
			shootdown.addr = addr;
			shootdown.pages = pages;
			cpu_send_message(cpu, CPU_FLUSH_TLB, &shootdown, true);

			spin_unlock_irqrestore(l);
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

		new_mapping = vm_create_region_at(new_address, new_size >> PAGE_SHIFT,
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

bool limits_are_contained(struct vm_region *reg, unsigned long start, unsigned long limit)
{
	unsigned long reg_limit = reg->base + (reg->pages << PAGE_SHIFT);

	if(start <= reg->base && limit > reg->base)
		return true;
	if(reg->base <= start && reg_limit >= limit)
		return true;

	return false;
}

#define VM_UNMAP_EVERY_REGION_IN_RANGE_DEBUG			0

void vm_unmap_every_region_in_range(struct mm_address_space *as, unsigned long start,
				    unsigned long length)
{
	unsigned long limit = start + length;

#if VM_UNMAP_EVERY_REGION_IN_RANGE_DEBUG
	sched_enable_preempt();

	printk("Unmapping from %lx to %lx\n", start, limit);
#endif

begin: ;
	struct rb_itor it;
	it.node = NULL;
	it.tree = as->area_tree;

	bool node_valid = rb_itor_first(&it);

	while(node_valid)
	{
		void **pp = rb_itor_datum(&it);
		assert(pp != NULL);

		struct vm_region *reg = *pp;

#if	VM_UNMAP_EVERY_REGION_IN_RANGE_DEBUG
		printk("Testing if %lx - %lx overlaps with %lx - %lx: ", reg->base,
			   reg->base + (reg->pages << PAGE_SHIFT), start, limit);
#endif
		if(!limits_are_contained(reg, start, limit))
		{
#if VM_UNMAP_EVERY_REGION_IN_RANGE_DEBUG
			printk("no\n");
#endif
			node_valid = rb_itor_next(&it);
			if(!node_valid)
				break;
			continue;
		}

#if VM_UNMAP_EVERY_REGION_IN_RANGE_DEBUG
		printk("yes\n");
#endif

		unsigned long reg_len = reg->pages << PAGE_SHIFT;
		unsigned long reg_addr = reg->base < start ? start : reg->base;
		unsigned long to_unmap = limit - reg_addr < reg_len
			? limit - reg_addr : reg_len;

		if(to_unmap == 0)
			break;
#if VM_UNMAP_EVERY_REGION_IN_RANGE_DEBUG
		printk("__vm_munmap %lx - %lx\n", reg_addr, reg_addr + to_unmap);
#endif
		int st = __vm_munmap(as, (void *) reg_addr, to_unmap);

		assert(st == 0);

		goto begin;
	}

#if VM_UNMAP_EVERY_REGION_IN_RANGE_DEBUG
	sched_disable_preempt();
#endif
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
		return NULL;
	
	if(!reg->vmo)
		return NULL;

	struct vm_object *vmo = reg->vmo;

	unsigned long off = reg->offset + ((unsigned long) page - reg->base);
	struct page *p = vmo_get(vmo, off, VMO_GET_MAY_POPULATE);
	if(!p)
		return NULL;
	
	if(!map_pages_to_vaddr(page, page_to_phys(p), PAGE_SIZE, reg->rwx))
	{
		page_unpin(p);
		return NULL;
	}

	page_unpin(p);

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
		size_t poff = (size_t) rb_itor_key(&it);

		if(poff >= end_off)
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
	assert(paging_write_protect(vaddr, mm) == true);

	__vm_invalidate_range((unsigned long) vaddr, 1, mm);
}

void vm_wp_page_for_every_region(struct page *page, size_t page_off, struct vm_object *vmo)
{
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

/* TODO: Add a safe way to find out what physical address is mapped to what virtual address(handles COW, WP, etc),
 * Fix mprotect changing up write-protects, probably merge mprotect and munmap code into generic "split up region"
 * code. Fix vm_mmap's return values(returning (void *) -errno isn't nice to check for in kernel code and we should
 * probably make sys_mmap return -errno if vm_mmap returns NULL(meaning error)). Verify lock safety. Change the lock
 * to a mutex.
 */

int get_phys_pages_direct(unsigned long addr, unsigned int flags, struct page **pages, size_t nr_pgs)
{
	if(flags & GPP_USER)
		return GPP_ACCESS_FAULT;

	/* This is a PFNMAP kind of thing, so we don't have pages to reference.
	 * We'll just need to pretend each paddr is a page struct and tell the caller at the
	 * end, using GPP_ACCESS_PFNMAP.
	 */

	for(size_t i = 0; i < nr_pgs; i++, addr += PAGE_SIZE)
	{
		unsigned long paddr = addr - PHYS_BASE;
		struct page *p = phys_to_page(paddr);
		pages[i] = p;
		page_ref(p);
	}

	return GPP_ACCESS_OK | GPP_ACCESS_PFNMAP;
}

int gpp_try_to_fault_in(unsigned long addr, struct vm_region *entry, unsigned int flags)
{
	struct fault_info finfo;
	finfo.error = 0;
	finfo.exec = false;
	finfo.fault_address = addr;
	finfo.ip = 0;
	finfo.read = flags & GPP_READ;
	finfo.user = true;
	finfo.write = flags & GPP_WRITE;

	if(__vm_handle_pf(entry, &finfo) < 0)
	{
		return GPP_ACCESS_FAULT;
	}

	return GPP_ACCESS_OK;
}

int __get_phys_pages(struct vm_region *region, unsigned long addr, unsigned int flags,
                     struct page **pages, size_t nr_pgs)
{
	unsigned long page_rwx_mask = (flags & GPP_READ ? PAGE_PRESENT : 0) |
                                  (flags & GPP_WRITE ? PAGE_WRITABLE : 0) |
								  (flags & GPP_USER ? PAGE_USER : 0);

	for(size_t i = 0; i < nr_pgs; i++, addr += PAGE_SIZE)
	{
retry: ;
		unsigned long mapping_info = get_mapping_info((void *) addr);

		if((mapping_info & page_rwx_mask) != page_rwx_mask)
		{
			int st = gpp_try_to_fault_in(addr, region, flags);

			if(!(st & GPP_ACCESS_OK))
				return st;
			goto retry;
		}

		unsigned long paddr = MAPPING_INFO_PADDR(mapping_info);

		struct page *page = phys_to_page(paddr);

		pages[i] = page;
	}

	return GPP_ACCESS_OK;
}

int get_phys_pages(void *_addr, unsigned int flags, struct page **pages, size_t nr_pgs)
{
	bool is_user = flags & GPP_USER;
	int ret = GPP_ACCESS_OK;
	size_t number_of_pages = nr_pgs;

	struct mm_address_space *as = is_user ? get_current_address_space() : &kernel_address_space;

	spin_lock(&as->vm_spl);

	unsigned long addr = (unsigned long) _addr;

	if(addr >= PHYS_BASE && (addr + (nr_pgs << PAGE_SHIFT)) < PHYS_BASE_LIMIT)
	{
		ret = get_phys_pages_direct(addr, flags, pages, nr_pgs);
		goto out;
	}

	size_t pages_gotten = 0;

	while(nr_pgs)
	{
		struct vm_region *reg = vm_find_region((void *) addr);

		if(!reg)
		{
			ret = GPP_ACCESS_FAULT;
			goto out;
		}

		/* Do a permission check. */
		unsigned int rwx_mask = (flags & GPP_READ ? 0 : 0) |
        	                    (flags & GPP_WRITE ? VM_WRITE : 0) |
	        	                (flags & GPP_USER ? VM_USER : 0);
	
		if((reg->rwx & rwx_mask) != rwx_mask)
		{
			ret = GPP_ACCESS_FAULT;
			goto out;
		}

		/* Calculate the number of pages we can resolve in this region */
		size_t vm_region_off_pgs = (reg->base - addr) >> PAGE_SHIFT;
		size_t max_resolved_pgs = reg->pages - vm_region_off_pgs;
		size_t resolved_pgs = min(nr_pgs, max_resolved_pgs);

		/* And now resolve stuff */
		ret = __get_phys_pages(reg, addr, flags, pages + pages_gotten, resolved_pgs);

		/* Bail if we've hit an error */
		if(!(ret & GPP_ACCESS_OK))
			goto out;

		nr_pgs -= resolved_pgs;
		pages_gotten += resolved_pgs;
		addr += nr_pgs << PAGE_SHIFT;
	}


	/* Now that we're done, we're pinning the pages we just got */

	for(size_t i = 0; i < number_of_pages; i++)
		page_pin(pages[i]);

out:
	spin_unlock(&as->vm_spl);

	return ret;
}
