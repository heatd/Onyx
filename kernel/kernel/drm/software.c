/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <onyx/vfs.h>
#include <onyx/dev.h>
#include <onyx/vmm.h>
#include <onyx/module.h>
#include <onyx/log.h>
#include <onyx/drm.h>
#include <onyx/framebuffer.h>
#include <onyx/drm-cookies.h>

#include <drm/drm.h>

#define MPRINTF(...) printf("drm: " __VA_ARGS__)

void soft_dumb_buffer_die(struct drm_object *object)
{
	struct drm_dumb_buffer *dbuf = (struct drm_dumb_buffer *) object;

	free_pages(dbuf->pages);
	free(dbuf);
}

struct drm_dumb_buffer *drm_soft_dumb_create(struct drm_dumb_buffer_info *info, struct drm_device *dev)
{
	size_t size = info->width * info->height * info->bpp/8;
	
	/* Allocate the fb in pages so it can be mapped */
	struct page *page_list = get_phys_pages(vmm_align_size_to_pages(size), 0);

	if(!page_list)
		return NULL;

	struct drm_dumb_buffer *buffer = zalloc(sizeof(*buffer));

	if(!buffer)
	{
		free_pages(page_list);
		return NULL;
	}

	drm_object_init(&buffer->object, soft_dumb_buffer_die,
		dev, DRM_COOKIE_DUMB_BUFFER);

	buffer->buffer = map_page_list(page_list, size, VM_WRITE | VM_GLOBAL | VM_NOEXEC);
	if(!buffer->buffer)
	{
		free_pages(page_list);
		free(buffer);
		return NULL;
	}

	off_t curr_off = 0;
	for(struct page *p = page_list; p != NULL; p = p->next_un.next_allocation, curr_off += PAGE_SIZE)
	{
		p->off = curr_off;
	}

	buffer->pages = page_list;
	buffer->size = size;

	info->size = size;
	info->stride = info->width * info->bpp/8;

	return buffer;
}

int drm_soft_swap_buffers(struct drm_object *buffer, struct drm_device *dev)
{
	if(buffer->object_cookie != DRM_COOKIE_DUMB_BUFFER)
		return -EINVAL;

	struct drm_dumb_buffer *buf = (struct drm_dumb_buffer *) buffer;

	struct framebuffer *fb = dev->fb;

	memcpy(fb->framebuffer, buf->buffer, buf->size);

	return 0;
}

int drm_init_software_dev(void)
{
	struct drm_device *device = zalloc(sizeof(*device));
	if(!device)
		return -1;

	device->name = "DRM Software Renderer";
	device->fb = get_primary_framebuffer();
	device->d_ops.dumb_create = drm_soft_dumb_create;
	device->d_ops.swap_buffers = drm_soft_swap_buffers;

	drm_add_device(device);
	return 0;
}