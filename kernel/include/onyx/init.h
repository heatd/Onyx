/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_INIT_H
#define _ONYX_INIT_H

#include <onyx/compiler.h>
#include <onyx/utils.h>

enum INIT_LEVEL
{
	INIT_LEVEL_VERY_EARLY_CORE = 0,
	INIT_LEVEL_VERY_EARLY_PLATFORM,
	INIT_LEVEL_EARLY_CORE_KERNEL,
	INIT_LEVEL_EARLY_PLATFORM,
	INIT_LEVEL_CORE_PLATFORM,
	INIT_LEVEL_CORE_INIT,
	INIT_LEVEL_CORE_AFTER_SCHED,
	INIT_LEVEL_CORE_KERNEL,
	INIT_LEVEL_CORE_PERCPU_CTOR
};

#define __INIT_ENTRY(func, x)		__attribute__((section(".init.level" # x), used, aligned(1))) \
static void (*__PASTE(func, __COUNTER__))(void) = func


#define __INIT_ENTRY_PERCPU(func, x)		__attribute__((section(".init.level" # x), used, aligned(1))) \
static void (*__PASTE(func, __COUNTER__))(unsigned int) = func

#define INIT_LEVEL_VERY_EARLY_CORE_ENTRY(func)		__INIT_ENTRY(func, 0)
#define INIT_LEVEL_VERY_EARLY_PLATFORM_ENTRY(func)  __INIT_ENTRY(func, 1)
#define INIT_LEVEL_EARLY_CORE_KERNEL_ENTRY(func)    __INIT_ENTRY(func, 2)
#define INIT_LEVEL_EARLY_PLATFORM_ENTRY(func)       __INIT_ENTRY(func, 3)
#define INIT_LEVEL_CORE_PLATFORM_ENTRY(func)        __INIT_ENTRY(func, 4)
#define INIT_LEVEL_CORE_INIT_ENTRY(func)            __INIT_ENTRY(func, 5)
#define INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(func)     __INIT_ENTRY(func, 6)
#define INIT_LEVEL_CORE_KERNEL_ENTRY(func)          __INIT_ENTRY(func, 7)
#define INIT_LEVEL_CORE_PERCPU_CTOR(func)          __INIT_ENTRY_PERCPU(func, 8)

void do_init_level(unsigned int level);
void do_init_level_percpu(unsigned int level, unsigned int cpu);

#endif
