/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PAGECACHE_H
#define _PAGECACHE_H

#include <kernel/list.h>
#include <kernel/vfs.h>

struct page_cache
{
	void *page;
	vfsnode_t *node; /* IF it's actually a file */
};

#define PAGE_CACHE_SIZE 65536 /* Each component of the cache has 64KiB */
void *add_to_cache(void *data, vfsnode_t *node);
#endif