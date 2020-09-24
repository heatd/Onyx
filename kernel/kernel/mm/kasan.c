/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <onyx/compiler.h>
#include <onyx/panic.h>
#include <onyx/vm.h>
#include <onyx/page.h>
#include <onyx/vm_layout.h>
#include <onyx/mm/kasan.h>

#include <onyx/percpu.h>

#define KADDR_SPACE_SIZE	0x800000000000
#define KADDR_START		0xffff800000000000

#define __alias(symbol)                 __attribute__((__alias__(#symbol)))

#define KASAN_SHIFT		3
#define KASAN_N_MASK		0x7
#define KASAN_ACCESSIBLE	0x0
#define KASAN_REDZONE		-1
#define KASAN_FREED		-2


bool kasan_is_init = false;

#define ADDR_SPACE_SIZE		(KADDR_SPACE_SIZE/8)

const unsigned long kasan_space = arch_high_half + arch_kasan_off;

bool kasan_is_cleared_access(unsigned long addr, size_t size)
{
	if(addr + size <= arch_low_half_max && addr < arch_low_half_max)
		return true;
	if(addr >= PHYS_BASE && addr + size <= PHYS_BASE + 0x80000000000)
		return true;
	if(addr >= kasan_space && addr + size <= kasan_space + ADDR_SPACE_SIZE)
		return true;
	return false;
}

static inline char *kasan_get_ptr(unsigned long addr)
{
	return (char *) (kasan_space + ((addr - arch_high_half) >> KASAN_SHIFT));
}

void vterm_panic(void);

void kasan_fail(unsigned long addr, size_t size, bool write, unsigned char b)
{
	/* Disable kasan so we can panic */
	kasan_is_init = false;

	vterm_panic();
	const char *event;
	const char *thing_accessed = "Accessed zone not marked as accessible";

	switch((char) b)
	{
		case KASAN_FREED:
			event = "use-after-free";
			thing_accessed = "Accessed zone marked KASAN_FREED";
			break;
		case KASAN_REDZONE:
			thing_accessed = "Accessed zone marked KASAN_REDZONE";
			__attribute__ ((fallthrough));
		default:
			event = "invalid access";
			break;
	};

	printk("\n=============================================================================================\n\n");

	char buffer[200] = {0};
	snprintf(buffer, 200, "kasan: "
		"detected memory error (%s) at %lx, %s of size %lu\nMemory error: %s(kasan code %x)",
		event, addr, write ? "write" : "read", size, thing_accessed, b);
	panic(buffer);
}

#define KASAN_MISALIGNMENT(x)	(x & (8-1))

void kasan_check_memory_fast(unsigned long addr, size_t size, bool write)
{
	char b = *kasan_get_ptr(addr);

	unsigned int n = addr & KASAN_N_MASK;

	if(b == KASAN_ACCESSIBLE)
		return;

	if(b < 0)
	{
		kasan_fail(addr, size, write, b);
	}

	unsigned int first_n_accessible = b;

	if(n > first_n_accessible || n + size > first_n_accessible)
		kasan_fail(addr, size, write, b);
}

void kasan_check_memory(unsigned long addr, size_t size, bool write)
{
	if(!kasan_is_init)
		return;

	size_t n = KASAN_MISALIGNMENT(addr);

	if(kasan_is_cleared_access(addr, size))
	{
		return;
	}

	if(n + size <= 8 && n == 0)
	{
		kasan_check_memory_fast(addr, size, write);
		return;
	}

	while(size != 0)
	{
		char b = *kasan_get_ptr(addr);

		unsigned int n = addr & KASAN_N_MASK;
		size_t to_set = size < 8 - n ? size : 8 - n;

		if(b == KASAN_ACCESSIBLE)
		{
			addr += to_set;
			size -= to_set;
		}
		else
		{
			if(b < 0)
				kasan_fail(addr, size, write, b);
			unsigned int first_n_accessible = b;

			if(n > first_n_accessible || n + to_set > first_n_accessible)
				kasan_fail(addr, size, write, b);
			
			addr += to_set;
			size -= to_set;
		}
	}

	kasan_is_init = true;
}

#define KASAN_LOAD(size)                     \
USED                                         \
void __asan_load##size(unsigned long addr) 	 \
{                                            \
	kasan_check_memory(addr, size, false);	 \
}						                     \
						                     \
USED			                             \
void __asan_load##size##_noabort(unsigned long addr) __alias(__asan_load##size);

#define KASAN_STORE(size)                    \
USED                                         \
void __asan_store##size(unsigned long addr)  \
{						                     \
	kasan_check_memory(addr, size, true);	 \
}						                     \
                                             \
USED                                         \
void __asan_store##size##_noabort(unsigned long addr) __alias(__asan_store##size);


KASAN_LOAD(1);
KASAN_LOAD(2);
KASAN_LOAD(4);
KASAN_LOAD(8);
KASAN_LOAD(16);

KASAN_STORE(1);
KASAN_STORE(2);
KASAN_STORE(4);
KASAN_STORE(8);
KASAN_STORE(16);

USED
void __asan_loadN(unsigned long addr, size_t size)
{
	kasan_check_memory(addr, size, false);
}

USED
void __asan_loadN_noabort(unsigned long addr, size_t size) __alias(__asan_loadN);

USED
void __asan_storeN(unsigned long addr, size_t size)
{
	kasan_check_memory(addr, size, true);
}

USED
void __asan_storeN_noabort(unsigned long addr, size_t size) __alias(__asan_storeN);

USED
void __asan_handle_no_return(void) {}

USED
void __asan_before_dynamic_init(void) {}

USED
void __asan_after_dynamic_init(void) {}

static bool asan_visit_region(struct vm_region *region)
{
	unsigned long region_start = region->base;
	unsigned long region_end = region->base + (region->pages << PAGE_SHIFT);

	if(region->type != VM_TYPE_HEAP)
		kasan_alloc_shadow(region_start, region_end - region_start, true);

	return true;
}

void kasan_init(void)
{
	vm_for_every_region(&kernel_address_space, asan_visit_region);
	kasan_is_init = true;
}

int kasan_alloc_shadow(unsigned long addr, size_t size, bool accessible)
{
	unsigned long kasan_start = (unsigned long) kasan_get_ptr(addr);
	unsigned long kasan_end = (unsigned long) kasan_get_ptr(addr + size);

	unsigned long actual_start = kasan_start, actual_end = kasan_end;

	/* Align the boundaries */

	kasan_start &= ~(PAGE_SIZE - 1);

	if(kasan_end & (PAGE_SIZE - 1))
	{
		kasan_end += PAGE_SIZE - (kasan_end & (PAGE_SIZE - 1));
	}

	/*printf("Kasan start: %lx\n", kasan_start);
	printf("Kasan end: %lx\n", kasan_end);
	printf("Actual start: %lx\nActual end: %lx\n", actual_start, actual_end);*/
	/* TODO: This is a huge memory leak right now. */
	assert(vm_map_range((void *) kasan_start, (kasan_end - kasan_start) >> PAGE_SHIFT,
		VM_WRITE | VM_NOEXEC | VM_DONT_MAP_OVER) != NULL);
	/* Mask excess bytes as redzones */
	/* memset((void *) kasan_start, KASAN_REDZONE, actual_start - kasan_start);
	memset((void *) actual_end, KASAN_REDZONE, kasan_end - actual_end);*/

	if(!accessible)
	{
		memset((void *) actual_start, (unsigned char) KASAN_REDZONE, actual_end - actual_start);
	}

	return 0;
}

void kasan_set_state(unsigned long *__ptr, size_t size, int state)
{
	unsigned long addr = (unsigned long) __ptr;
	/* State: 0 = Accessible, -1 = redzone, 1 = freed */
	while(size)
	{
		size_t n = KASAN_MISALIGNMENT(addr);
		size_t to_set = size < 8 - n ? size : 8 - n;

		char *ptr = kasan_get_ptr(addr);
		unsigned char byte;

		if(state == 0)
			byte = to_set != 8 ? to_set : KASAN_ACCESSIBLE;
		else if(state < 0)
			byte = KASAN_REDZONE;
		else
			byte = KASAN_FREED;

		*ptr = byte;

		size -= to_set;
		addr += to_set;
	}
}
