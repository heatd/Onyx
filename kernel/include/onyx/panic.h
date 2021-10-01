/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_PANIC_H
#define _ONYX_PANIC_H

#include <stdint.h>
#include <multiboot2.h>
#include <onyx/registers.h>


#ifdef __cplusplus
extern "C" {
#endif

void halt();
/* The functions halt and get_thread_ctx are architecture dependent, as they require manual assembly.
 * As so, its left for the architecture to implement these functions. The kernel expects them to be hooked.
 */

/* panic - Panics the system (dumps information and halts) */
__attribute__ ((noreturn, noinline))
void panic(const char* msg, ...);

/* This does not compile in C++ */
void init_elf_symbols(struct multiboot_tag_elf_sections *secs);
void elf_sections_reserve(struct multiboot_tag_elf_sections * secs);

void stack_trace_ex(uint64_t *stack);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <stdio.h>

template <typename T>
[[noreturn]]
void panic_bounds_check(T* arr, bool is_vec, unsigned long bad_index)
{
	const char *type = is_vec ? "vector" : "array";
	printk("%s::operator[] detected a bad access with index %lu\n",
		type, bad_index);
	printk("%s address: %p\n", type, arr);
	panic("array bounds check");
}
#endif

#endif
