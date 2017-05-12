/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <errno.h>

#include <kernel/vmm.h>
#include <kernel/pagecache.h>

static struct list_head page_list = {0};

void *add_to_cache(void *data, vfsnode_t *file)
{
	void *pages = vmalloc(16, VM_TYPE_REGULAR, VM_WRITE | VM_NOEXEC);
	if(!pages)
		return errno = ENOMEM, NULL;
	memcpy(pages, data, 64 * 1024);
	struct page_cache *c = malloc(sizeof(struct page_cache));
	if(!c)
	{
		vfree(pages, 16);
		return errno = ENOMEM, NULL;
	}
	c->page = pages;
	c->node = file;
	
	struct list_head *it = &page_list;
	if(!page_list.ptr)
	{
		page_list.ptr = (void*) c;
	}
	else
	{
		while(it->next) it = it->next;

		it->next = malloc(sizeof(struct list_head));
		if(!it->next)
		{
			free(c);
			vfree(pages, 16);
			return errno = ENOMEM, NULL;
		}
		it->next->ptr = c;
		it->next->next = NULL;
	}
	return c->page;
}

