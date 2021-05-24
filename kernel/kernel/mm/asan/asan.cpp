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
#include <onyx/utility.hpp>

#include <onyx/percpu.h>

#define KADDR_SPACE_SIZE	0x800000000000
#define KADDR_START		0xffff800000000000

#define __alias(symbol)                 __attribute__((__alias__(#symbol)))

#define KASAN_SHIFT         3
#define KASAN_N_MASK		((1 << KASAN_SHIFT) - 1)
#define KASAN_ACCESSIBLE	0x0
#define KASAN_REDZONE       0xff
#define KASAN_FREED         0xfe


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

	switch((unsigned char) b)
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

#define KASAN_MISALIGNMENT(x)	((x) & KASAN_N_MASK)

void kasan_check_memory_fast(unsigned long addr, size_t size, bool write)
{
	char b = *kasan_get_ptr(addr);

	unsigned int n = KASAN_MISALIGNMENT(addr);

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

	size_t n_ = KASAN_MISALIGNMENT(addr);

	if(kasan_is_cleared_access(addr, size))
	{
		return;
	}

	if(n_ + size <= 8 && n_ == 0)
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


extern "C"
{

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

USED void __asan_report_store_n_noabort(unsigned long addr, size_t size)
{
	kasan_check_memory(addr, size, true);
}

USED void __asan_report_load_n_noabort(unsigned long addr, size_t size)
{
	kasan_check_memory(addr, size, false);
}

USED
void __asan_handle_no_return(void) {}

USED
void __asan_before_dynamic_init(void) {}

USED
void __asan_after_dynamic_init(void) {}

USED void __asan_register_globals(){}
USED void __asan_unregister_globals(){}

#define ASAN_REPORT_ERROR(type, is_write, size)                       \
                                                                       \
	USED void __asan_report_##type##size(unsigned long addr) {                   \
		kasan_check_memory(addr, size, is_write);    \
	}                                                                   \
	USED void __asan_report_exp_##type##size(unsigned long addr, uint32_t exp) { \
		kasan_check_memory(addr, size, is_write);    \
	}                                                                   \
	                                                                    \
	USED void __asan_report_##type##size##_noabort(unsigned long addr) {         \
		kasan_check_memory(addr, size, is_write);    \
  	}

ASAN_REPORT_ERROR(load, false, 1)
ASAN_REPORT_ERROR(load, false, 2)
ASAN_REPORT_ERROR(load, false, 4)
ASAN_REPORT_ERROR(load, false, 8)
ASAN_REPORT_ERROR(load, false, 16)
ASAN_REPORT_ERROR(store, true, 1)
ASAN_REPORT_ERROR(store, true, 2)
ASAN_REPORT_ERROR(store, true, 4)
ASAN_REPORT_ERROR(store, true, 8)
ASAN_REPORT_ERROR(store, true, 16)

USED
int __asan_option_detect_stack_use_after_return = 0;
USED unsigned long __asan_shadow_memory_dynamic_address = kasan_space;

#define DEFINE_ASAN_SET_SHADOW(byte) \
USED \
void __asan_set_shadow_##byte(const void *addr, size_t size)	\
{								\
	memset((void *)addr, 0x##byte, size);			\
}								\

DEFINE_ASAN_SET_SHADOW(00);
DEFINE_ASAN_SET_SHADOW(f1);
DEFINE_ASAN_SET_SHADOW(f2);
DEFINE_ASAN_SET_SHADOW(f3);
DEFINE_ASAN_SET_SHADOW(f5);
DEFINE_ASAN_SET_SHADOW(f8);

USED
void __asan_init() {}
USED
void __asan_version_mismatch_check_v8() {}

USED
void* __asan_memcpy(void* dst, const void* src, size_t n)
{
	if(n == 0)
		return dst;
	
	kasan_check_memory((unsigned long) dst, n, true);
	kasan_check_memory((unsigned long) src, n, false);

	return memcpy(dst, src, n);
}

USED
void* __asan_memmove(void* dst, const void* src, size_t n)
{
	if(n == 0)
		return dst;
	
	kasan_check_memory((unsigned long) dst, n, true);
	kasan_check_memory((unsigned long) src, n, false);

	return memmove(dst, src, n);
}

USED
void* __asan_memset(void* dst, int c, size_t n)
{
	if(n == 0)
		return dst;
	
	kasan_check_memory((unsigned long) dst, n, true);
	return memset(dst, c, n);
}

}

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

void platform_serial_write(const char *s, size_t size);

extern "C"
void asan_poison_shadow(unsigned long addr, size_t size, uint8_t value)
{

#if 0
	if()
	{
		char buf[100];
		snprintf(buf, 100, "poisoning [%lx, %lx]\n", addr, addr + size);

		platform_serial_write(buf, strlen(buf));
	}
#endif

	auto shadow_start = kasan_get_ptr(addr);
	auto shadow_end = kasan_get_ptr(addr + size);

	uint8_t offset = KASAN_MISALIGNMENT(addr);
	uint8_t end_leftover = KASAN_MISALIGNMENT(addr + size);

	if(shadow_start == shadow_end)
	{
		// We're only poisoning a single byte of shadow
		// See if any part of the byte was already poisoned or not, and if so extend it

		auto shadow_val = *shadow_start;
		if(shadow_val > 0)
		{
			// This byte is partially poisoned, lets check if there's no holes in our new poisoning.
			if(offset + size == (uint8_t) shadow_val)
			{
				// This works! Check for a partial poisoning vs a complete one
				*shadow_start = offset == 0 ? value : offset;
			}
			else
			{
				// Is this valid?
				panic("bug?");
			}
		}
		else if(shadow_val > 0 && offset != 0)
		{
			// Is this valid?
			panic("bug?");
		}

		return;
	}

	if(offset != 0)
	{
		// same question as above
		assert(offset + size >= sizeof(uint8_t));
		// Lets poison the first byte like we did up there
		if(shadow_start[0] == 0)
			shadow_start[0] = offset;
		else if(shadow_start[0] > 0)
		{
			shadow_start[0] = cul::min(offset, (uint8_t) shadow_start[0]);
		}

		shadow_start++;
	}

	memset(shadow_start, value, shadow_end - shadow_start);

	if(end_leftover != 0)
	{
		// Check for a partial poisoning at the end, and try to do it if we can complete the byte
		auto val = shadow_end[0];
		if(val > 0 && end_leftover == val)
		{
			shadow_end[0] = value;
		}
	}
}

void asan_unpoison_shadow(unsigned long addr, size_t size)
{
	auto shadow_start = kasan_get_ptr(addr);
	auto shadow_end = kasan_get_ptr(addr + size);

	uint8_t offset = KASAN_MISALIGNMENT(addr);
	uint8_t end_leftover = KASAN_MISALIGNMENT(addr + size);

	assert(offset == 0);

	memset(shadow_start, 0, shadow_end - shadow_start);

	if(end_leftover != 0)
	{
		// entire byte is poisoned, unpoison the start
		if(shadow_end[0] < 0)
		{
			shadow_end[0] = offset;
		}
		else if(shadow_end[0] > 0)
		{
			// try to increse the unpoisoned region
			shadow_end[0] = cul::max(offset, (uint8_t) shadow_end[0]);
		}
	}
}

extern "C"
void kasan_set_state(unsigned long *__ptr, size_t size, int state)
{
	unsigned long addr = (unsigned long) __ptr;

	if(state == 0)
		asan_unpoison_shadow(addr, size);
	else
		asan_poison_shadow(addr, size, state == 1 ? KASAN_FREED : KASAN_REDZONE);
}
