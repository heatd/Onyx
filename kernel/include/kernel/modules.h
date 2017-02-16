/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_MODULES_H
#define _KERNEL_MODULES_H

#include <stdint.h>
#include <string.h>

#include <kernel/elf.h>
typedef struct mod
{
	const char *path;
	const char *name;
	void *base_address;
	size_t size;
	struct mod *next;
	module_fini_t fini;
} module_t;

typedef struct
{
	size_t size;
	module_t **buckets;
} module_hashtable_t;

int load_module(const char *path, const char *name);
int initialize_module_subsystem();
void *allocate_module_memory(size_t size);
#endif