/*
* Copyright (c) 2019 Pedro Falcato
* This file is a part of Onyx, and is released under the terms of the MIT License
* - check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_HEAP_H
#define _KERNEL_HEAP_H

#include <stdint.h>

struct heap
{
	void *starting_address;
	void *brk;
	unsigned long size;
};

struct heap *heap_get(void);
size_t heap_get_used_pages(void);

#endif
