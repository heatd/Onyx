/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PUBLIC_MEMSTAT_H
#define _ONYX_PUBLIC_MEMSTAT_H

#include <stddef.h>

struct memstat
{
	size_t total_pages;
	size_t allocated_pages;
	size_t page_cache_pages;
	size_t kernel_heap_pages;
};

#endif