/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _PAGECACHE_H
#define _PAGECACHE_H

#include <kernel/list.h>
#include <kernel/vfs.h>

struct page_cache
{
	void *page;
	vfsnode_t *node; /* IF it's actually a file */
};

void *add_to_cache(void *data, vfsnode_t *node);
#endif