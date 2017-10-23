/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <onyx/user.h>
#include <onyx/mm/shm.h>
#include <onyx/vmm.h>
#include <onyx/mutex.h>
#include <onyx/file.h>
#include <onyx/list.h>
#include <onyx/page.h>

#include <fcntl.h>

#include <sys/stat.h>

static mutex_t shm_lock;
static struct shm_region *shms = NULL;

void *shm_mmap(struct vm_entry *area, struct inode *node)
{
	struct shm_region *shm = node->helper;
	off_t offset = area->offset;
	if(offset & (PAGE_SIZE-1))
		return (void*) -EINVAL;
	if(node->size < (size_t) offset)
		return (void*) -EINVAL;

	size_t page_idx = offset / PAGE_SIZE;
	size_t nr_pages = area->pages;

	if(area->pages * PAGE_SIZE > node->size)
		return (void*) -EINVAL;
	uintptr_t vaddr = area->base;

	struct list_head *l = &shm->pages;

	for(size_t i = 0; i < page_idx; i++) l = l->next;

	for(size_t i = 0; i < nr_pages; i++)
	{
		struct page *p = l->ptr;
		if(!paging_map_phys_to_virt(vaddr, (uintptr_t) p->paddr, area->rwx))
			return (void*) -ENOMEM;
		vaddr += PAGE_SIZE;
		l = l->next;
	}
	return (void*) area->base;
}

int shm_add_pages(size_t nr_pages, struct shm_region *shm)
{
	for(size_t i = 0; i < nr_pages; i++)
	{
		void *p = __alloc_page(0);
		if(!p)
			return -ENOMEM;
		struct page *page = phys_to_page((uintptr_t) p);
		page_increment_refcount(p);
		if(!shm->pages.ptr)
			shm->pages.ptr = page;
		else
			list_add(&shm->pages, &page);
	}
	return 0;
}

int shm_ftruncate(off_t len, struct inode *vnode)
{
	/* TODO: This isn't very correct, tofix. */
	off_t diff = len - vnode->size;
	struct shm_region *shm = vnode->helper;

	vnode->size = len;
	shm->size = len;

	if(diff > 0)
	{
		diff = (off_t) page_align_up((void*) diff);
		size_t nr_pages = vmm_align_size_to_pages(diff);

		return shm_add_pages(nr_pages, shm);
	}
	return 0;
}

void shm_append(struct shm_region *reg)
{
	mutex_lock(&shm_lock);
	
	if(!shms)
		shms = reg;
	else
	{
		struct shm_region *r = shms;
		while(r->next) r = r->next;
		r->next = reg;
	}

	mutex_unlock(&shm_lock);
}

struct shm_region *shm_find_region_posix(const char *name)
{
	for(struct shm_region *reg = shms; reg; reg = reg->next)
	{
		if(!reg->name)
			continue;
		if(!strcmp(reg->name, name))
			return reg;
	}
	return NULL;
}

struct shm_region *shm_create_region_posix(const char *name, int flags, mode_t mode)
{
	struct shm_region *region = zalloc(sizeof(struct shm_region));
	if(!region)
	{
		errno = ENOMEM;
		return NULL;
	}

	region->name = strdup(name);
	region->flags = flags;
	region->mode = mode;

	shm_append(region);
	
	return region;
}

struct shm_region *shm_open_region_posix(const char *name, int flags, mode_t mode)
{
	struct shm_region *r = shm_find_region_posix(name);
	if(r)
		return r;
	else if(flags & O_CREAT)
	{
		return shm_create_region_posix(name, flags, mode);
	}
	return NULL;
}

int create_shm_fd(struct shm_region *reg, int flags)
{
	if(!reg->vnode)
	{
		struct inode *node = zalloc(sizeof(struct inode));
		if(!node)
			return errno = ENOMEM, -1;
		node->type = VFS_TYPE_CHAR_DEVICE;
		node->fops.mmap = shm_mmap;
		node->fops.ftruncate = shm_ftruncate;
		node->helper = reg;

		reg->vnode = node;
	}

	int fd = open_with_vnode(reg->vnode, flags);
	return fd;
}

int sys_shm_open(const char *name, int flags, mode_t mode)
{
	int status = 0;
	char *str = strcpy_from_user(name);
	if(!str)
		return -errno;
	
	struct shm_region *r = shm_open_region_posix(str, flags, mode);
	if(!r)
	{
		status = -errno;
		goto cleanup;
	}

	r->refcount++;

	status = create_shm_fd(r, flags);

cleanup:
	free(str);
	return status;
}

int sys_shm_unlink(const char *name)
{
	return 0;
}
