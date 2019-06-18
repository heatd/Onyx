/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <onyx/panic.h>
#include <onyx/x86/vm_layout.h>

#define __alias(symbol)                 __attribute__((__alias__(#symbol)))

#define KASAN_SHIFT		3
#define KASAN_N_MASK		0x7
#define KASAN_ACCESSIBLE	0x0
#define KASAN_REDZONE		-1
#define KASAN_FREED		-2

bool kasan_is_init = false;

unsigned long kasan_space = arch_high_half + arch_kasan_off;

char *kasan_get_ptr(unsigned long addr)
{
	return (char *) (kasan_space + (addr >> KASAN_SHIFT));
}

void kasan_fail(unsigned long addr, size_t size, bool write)
{
	/* Disable kasan so we can panic */
	kasan_is_init = false;
	printk("Kasan: panic at %lx, %s of size %lu\n", addr, write ? "write" : "read", size);
	panic("Kasan");
}

#define KASAN_MISALIGNMENT(x)	(x & (8-1))

void kasan_check_memory_fast(unsigned long addr, size_t size, bool write)
{
	char b = *kasan_get_ptr(addr);

	unsigned int n = addr & KASAN_N_MASK;

	if(b == KASAN_ACCESSIBLE)
		return;
	
	unsigned int first_n_accessible = b;

	if(n >= first_n_accessible)
		kasan_fail(addr, size, write);
}

void kasan_check_memory(unsigned long addr, size_t size, bool write)
{
	if(!kasan_is_init)
		return;
	size_t n = KASAN_MISALIGNMENT(addr);

	if(n + size <= 8)
		kasan_check_memory_fast(addr, size, write);

	while(size != 0)
	{
		char b = *kasan_get_ptr(addr);

		unsigned int n = addr & KASAN_N_MASK;

		if(b == KASAN_ACCESSIBLE)
		{
			addr += 8 - n;
			size -= n;
		}
		else
		{
			unsigned int first_n_accessible = b;

			if(n >= first_n_accessible)
				kasan_fail(addr, size, write);
		}
	}
}

#define KASAN_LOAD(size) \
void __asan_load##size(unsigned long addr) 	\
{						\
	kasan_check_memory(addr, size, false);	\
}						\
__alias(__asan_load##size) \
void __asan_load##size##_noabort(unsigned long addr);

#define KASAN_STORE(size) \
void __asan_store##size(unsigned long addr) 	\
{						\
	kasan_check_memory(addr, size, true);	\
}						\
__alias(__asan_store##size) \
void __asan_store##size##_noabort(unsigned long addr);


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

void __asan_loadN(unsigned long addr, size_t size)
{
	kasan_check_memory(addr, size, false);
}
__alias(__asan_loadN)
void __asan_loadN_noabort(unsigned long addr, size_t size);

void __asan_storeN(unsigned long addr, size_t size)
{
	kasan_check_memory(addr, size, true);
}

__alias(__asan_storeN)
void __asan_storeN_noabort(unsigned long addr, size_t size);