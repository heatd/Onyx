/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>

#include <onyx/vm.h>
#include <onyx/panic.h>
#include <onyx/vfs.h>
#include <onyx/ioctx.h>

class test
{
public:
	virtual bool execute(){panic("bad test\n");};
	virtual bool execute_loads_of_times()
	{
		return false;
	}
	virtual const char *get_name()
	{
		return "bad test";
	}
};


template <typename T>
static bool is_unmapped(T *p, size_t size)
{
	unsigned long start = (unsigned long) p;
	unsigned long end = start + size;

	while(start != end)
	{
		if(virtual2phys((void *) start))
			return false;
		start += PAGE_SIZE;
	}

	auto vm_region = vm_find_region(p);
	assert(vm_region == nullptr);

	return true;
}

class vm_unmap_tests : public test
{
public:
	bool execute() override;
	const char *get_name() override
	{
		return "vm_unmap_tests";
	}

	bool check_for_present_pages(void *ptr)
	{
		char *p = (char *) ptr + 0x2000;
		if(!is_unmapped(p, 0x3000))
		{
			printk("vm_munmap did not unmap!\n");
			return false;
		}

		auto reg = vm_find_region(ptr);
		assert(reg != nullptr);
		if(reg->base + (reg->pages << PAGE_SHIFT) != (unsigned long) p)
		{
			printk("math does not check out\n");
			return false;
		}

		return true;
	}

	bool unmap_stuff(void *ptr)
	{
		struct memstat stat;
		page_get_stats(&stat);
		//printk("used_pages: %lu\n", stat.allocated_mem / 4096);

		char *p = (char *) ptr + 0x2000;
		if(vm_munmap(&kernel_address_space, (void *) (p + 0x3000), 1019 << PAGE_SHIFT) < 0)
		{
			printk("vm_munmap failed\n");
			return false;
		}

		if(vm_munmap(&kernel_address_space, (void *) ptr, 2 << PAGE_SHIFT) < 0)
		{
			printk("vm_munmap failed\n");
			return false;
		}
		page_get_stats(&stat);

		//printk("used_pages: %lu\n", stat.allocated_mem / 4096);

		return true;
	}

	static struct page *commit(size_t off, struct vm_object *vmo)
	{
		auto page = alloc_page(0);
		if(!page)
			return nullptr;
		return page;
	}

	auto do_mapping_shared() -> struct vm_region *
	{
		struct memstat stat;
		page_get_stats(&stat);

		//printk("shared used_pages: %lu\n", stat.allocated_mem / 4096);

		auto vmo = vmo_create(1024 << PAGE_SHIFT, nullptr);
		assert(vmo != nullptr);
		vmo->commit = commit;

		struct vm_region *vm =
		vm_allocate_virt_region(VM_KERNEL, 1024, VM_TYPE_REGULAR, VM_WRITE | VM_NOEXEC);
		if(!vm)
			return NULL;

		assert(vmo_assign_mapping(vmo, vm) >= 0);

		vm->vmo = vmo;
		vm->mapping_type = 1; // MAP_SHARED

		assert(vmo_prefault(vmo, 1024 << PAGE_SHIFT, 0) >= 0);

		assert(vm_flush(vm, 0, 0) >= 0);
		//printk("Ptr: %lx - %lx\n", (unsigned long) vm->base, (unsigned long) vm->base + (1024 << PAGE_SHIFT));

		return vm;
	}

	void *do_mapping_regular()
	{
		void *ptr = vmalloc(1024, VM_TYPE_REGULAR, VM_WRITE | VM_NOEXEC);
		if(!ptr)
		{
			printk("vmalloc failed\n");
			return NULL;;
		}
		//printk("Ptr: %lx - %lx\n", (unsigned long) ptr, (unsigned long) ptr + (1024 << PAGE_SHIFT));
		return ptr;
	}

	bool is_not_present_in_vmo(struct vm_object *vmo, unsigned long lower, unsigned long higher);
	bool execute_private();
	bool execute_shared();

	bool execute_loads_of_times() override
	{
		return false;
	}
};

bool vm_unmap_tests::is_not_present_in_vmo(struct vm_object *vmo, unsigned long lower, unsigned long higher)
{
	struct rb_itor it;
	it.node = nullptr;
	it.tree = vmo->pages;
	unsigned long pages_to_be_found = (higher - lower) >> PAGE_SHIFT;
	bool node_valid = rb_itor_first(&it);
	while(node_valid)
	{
		struct page *page = (struct page *) *rb_itor_datum(&it);
		size_t off = (size_t) rb_itor_key(&it);
	
		if(off >= lower && off < higher)
		{
			pages_to_be_found--;
			//printk("page offset %lx present!\n", page->off);
			if(pages_to_be_found == 0)
				return false;
			
		}
		node_valid = rb_itor_next(&it);
	}

	return true;
}

bool vm_unmap_tests::execute_shared()
{/* 
	struct memstat stat;
	page_get_stats(&stat);

	printk("shared used_pages: %lu\n", stat.allocated_mem / 4096);*/
	auto vm = do_mapping_shared();
	if(!vm)
		return false;
	void *ptr = (void *) vm->base;
	auto vmo = vm->vmo;

	char *p = (char *) ptr + 0x2000;
	auto st = vm_munmap(&kernel_address_space, (void *) p, 0x3000);
	if(st < 0)
	{
		printk("vm_munmap failed with %u\n", st);
		return false;
	}

	if(!check_for_present_pages(ptr))
		return false;
	if(is_not_present_in_vmo(vmo, 0x2000, 0x2000 + 0x3000))
		return false;

	return unmap_stuff(ptr);
}

bool vm_unmap_tests::execute_private()
{
	struct memstat stat;
	page_get_stats(&stat);

	//printk("private used_pages: %lu\n", stat.allocated_mem / 4096);
	auto ptr = do_mapping_regular();
	if(!ptr)
		return false;

	char *p = (char *) ptr + 0x2000;
	auto st = vm_munmap(&kernel_address_space, (void *) p, 0x3000);
	if(st < 0)
	{
		printk("vm_munmap failed with %u\n", st);
		return false;
	}

	if(!check_for_present_pages(ptr))
		return false;

	return unmap_stuff(ptr);
}

bool vm_unmap_tests::execute()
{
	if(!execute_private() || !execute_shared())
		return false;
	return true;
}

class vm_protect_tests : public test
{
private:

public:
	bool execute() override;
	bool execute_loads_of_times() override
	{
		return false;
	}

	const char *get_name() override
	{
		return "vm_protect_tests";
	}
};

bool vm_protect_tests::execute()
{
	void *ptr = vmalloc(1024, VM_TYPE_SHARED, VM_NOEXEC);
	assert(ptr != nullptr);

	struct vm_region *vm = vm_find_region(ptr);
	if(!vm)
	{
		printk("could not find vm!\n");
		return false;
	}

	vm_print_map();

	auto p = (unsigned long) ptr + 0x4000;
	vm_mprotect(&kernel_address_space, (void *) p, 10 << PAGE_SHIFT, VM_WRITE);
	printk("mprotecting from %lx to %lx\n", p, (unsigned long) p + (10 << PAGE_SHIFT));
	vm_print_map();

	return true;
}

vm_unmap_tests unmap_test{};
vm_protect_tests protect_test{};

static test *tests[] = 
{
	&unmap_test,
	&protect_test
};

bool execute_multiple_times(test *test)
{
	for(int i = 0; i < 1000; i++)
	{
		if(!test->execute())
			return false;
	}

	return true;
}

extern "C"
void execute_vm_tests()
{
	size_t nr_tests = sizeof(tests) / sizeof(tests[0]);
	for(size_t i = 0; i < nr_tests; i++)
	{
		bool should_do_multiple_times = tests[i]->execute_loads_of_times();
		bool st = false;
		if(should_do_multiple_times)
			st = execute_multiple_times(tests[i]);
		else
			st = tests[i]->execute();
		if(!st)
		{
			printk("Test %s(%lu) failed to execute\n", tests[i]->get_name(), i);
		}
		else
		{
			printk("Test %s executed successfully\n", tests[i]->get_name());
		}
	}
}