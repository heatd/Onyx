/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include <kernel/panic.h>
#include <kernel/dev.h>
#include <kernel/task_switching.h>
#include <kernel/vmm.h>
#include <kernel/pagecache.h>

static struct list_head page_list = {0};

struct page_cache *add_to_cache(void *data, size_t size, off_t offset, vfsnode_t *file)
{
	void *pages = vmalloc(16, VM_TYPE_REGULAR, VM_WRITE | VM_NOEXEC | VM_GLOBAL);
	if(!pages)
		return errno = ENOMEM, NULL;
	memcpy(pages, data, PAGE_CACHE_SIZE);
	struct page_cache *c = malloc(sizeof(struct page_cache));
	if(!c)
	{
		vfree(pages, 16);
		return errno = ENOMEM, NULL;
	}
	c->page = pages;
	c->node = file;
	c->size = size;
	c->offset = offset;
	c->lock = 0;
	c->dirty = 0;
	
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
	return c;
}
size_t __do_vfs_write(void *buf, size_t size, off_t off, vfsnode_t *this)
{
	struct minor_device *m = dev_find(this->dev);
	if(!m)
		return errno = ENODEV;
	if(!m->fops)
		return errno = ENOSYS;
	if(this->type & VFS_TYPE_MOUNTPOINT)
		return __do_vfs_write(buf, size, off, this->link);
	if(m->fops->write != NULL)
		return m->fops->write(off, size, buf, this);

	return errno = ENOSYS;
}
static thread_t *sync_thread;
void pagecache_sync()
{
repeat: ;
	struct list_head *list = &page_list;
	while(list->next && list->ptr)
	{
		struct page_cache *c = list->ptr;
		if(c->dirty)
		{
			__do_vfs_write(c->page, c->size, c->offset, c->node);
			c->dirty = 0;
		}
		list = list->next;
	}
	sync_thread->status = THREAD_SLEEPING;
	goto repeat;
}
void pagecache_init()
{
	sync_thread = sched_create_thread(pagecache_sync, 1, NULL);
	if(!sync_thread)
		panic("Could not spawn the sync thread!\n");
	sync_thread->status = THREAD_SLEEPING;
}
void wakeup_sync_thread()
{
	sync_thread->status = THREAD_RUNNABLE;
}
