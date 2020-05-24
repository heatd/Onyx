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
#include <onyx/vm.h>
#include <onyx/module.h>
#include <onyx/log.h>
#include <onyx/photon.h>
#include <onyx/framebuffer.h>
#include <onyx/photon-cookies.h>

#include <photon/photon.h>

#define MPRINTF(...) printf("photon: " __VA_ARGS__)

void soft_dumb_buffer_die(struct photon_object *object)
{
	struct photon_dumb_buffer *dbuf = (struct photon_dumb_buffer *) object;

	free_pages(dbuf->pages);
	free(dbuf);
}

struct photon_dumb_buffer *photon_soft_dumb_create(struct photon_dumb_buffer_info *info, struct photon_device *dev)
{
	size_t size = info->width * info->height * info->bpp/8;
	
	/* Allocate the fb in pages so it can be mapped */
	struct page *page_list = alloc_pages(vm_size_to_pages(size), 0);

	if(!page_list)
		return NULL;

	struct photon_dumb_buffer *buffer = zalloc(sizeof(*buffer));

	if(!buffer)
	{
		free_pages(page_list);
		return NULL;
	}

	photon_object_init(&buffer->object, soft_dumb_buffer_die,
		dev, PHOTON_COOKIE_DUMB_BUFFER);

	buffer->buffer = map_page_list(page_list, size, VM_WRITE  | VM_NOEXEC);
	if(!buffer->buffer)
	{
		free_pages(page_list);
		free(buffer);
		return NULL;
	}

	buffer->pages = page_list;
	buffer->size = size;

	info->size = size;
	info->stride = info->width * info->bpp/8;

	return buffer;
}

int photon_soft_swap_buffers(struct photon_object *buffer, struct photon_device *dev)
{
	if(buffer->object_cookie != PHOTON_COOKIE_DUMB_BUFFER)
		return -EINVAL;

	struct photon_dumb_buffer *buf = (struct photon_dumb_buffer *) buffer;

	struct framebuffer *fb = dev->fb;

	memcpy(fb->framebuffer, buf->buffer, buf->size);

	return 0;
}

int photon_init_software_dev(void)
{
	struct photon_device *device = zalloc(sizeof(*device));
	if(!device)
		return -1;

	device->name = "Photon Software Renderer";
	device->fb = get_primary_framebuffer();
	device->d_ops.dumb_create = photon_soft_dumb_create;
	device->d_ops.swap_buffers = photon_soft_swap_buffers;

	photon_add_device(device);
	return 0;
}
