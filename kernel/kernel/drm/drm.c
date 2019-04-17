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
#include <onyx/drm.h>
#include <onyx/framebuffer.h>
#include <onyx/process.h>
#include <onyx/drm-cookies.h>

#include <drm/drm.h>

#define MPRINTF(...) printf("drm: " __VA_ARGS__)

#define DRM_NR_ENTRIES		1024

struct drm_device *main_device = NULL;

int drm_add_device(struct drm_device *device)
{
	/* TODO: This shouldn't be this simple, refactor this part of the code
	 * after writing a gpu driver.
	*/
	object_init(&device->object, NULL);

	main_device = device;

	return 0;
}

struct drm_context *drm_get_context(pid_t pid, struct drm_device *dev)
{
	spin_lock_preempt(&dev->context_lock);
	for(struct drm_context *c = dev->per_process_context; c != NULL; c = c->next)
	{
		if(c->pid == pid)
		{
			spin_unlock_preempt(&dev->context_lock);
			return c;
		}
	}

	spin_unlock_preempt(&dev->context_lock);
	return NULL;
}

int drm_create_process_context(pid_t pid, struct drm_device *device)
{
	struct drm_context *c = zalloc(sizeof(*c));
	if(!c)
		return -1;
	c->pid = pid;

	spin_lock_preempt(&device->context_lock);
	struct drm_context **pp = &device->per_process_context;

	while(*pp)
		pp = &(*pp)->next;

	*pp = c;

	spin_unlock_preempt(&device->context_lock);
	return 0;
}

int drm_expand_handle_table(struct drm_context *ctx)
{
	/* This executes with a lock held */

	ctx->handle_table_entries += DRM_NR_ENTRIES;
	struct drm_object **table = (struct drm_object **) realloc(ctx->handle_table,
		ctx->handle_table_entries * sizeof(struct drm_object *));

	if(!table)
	{
		ctx->handle_table_entries -= DRM_NR_ENTRIES;
		return -1;
	}

	ctx->handle_table = table;

	return 0;
}

drm_handle try_add_drm_object(struct drm_context *ctx, struct drm_object *object)
{
	for(size_t i = 0; i < ctx->handle_table_entries; i++)
	{
		if(ctx->handle_table[i] != NULL)
		{
			ctx->handle_table[i] = object;
			return i;
		}
	}

	return DRM_INVALID_HANDLE;
}

drm_handle __drm_add_object(struct drm_context *ctx, struct drm_object *object)
{
	spin_lock_preempt(&ctx->handle_table_lock);

	drm_handle handle = 0;

	while((handle = try_add_drm_object(ctx, object)) == DRM_INVALID_HANDLE)
	{
		if(drm_expand_handle_table(ctx) < 0)
		{
			spin_unlock_preempt(&ctx->handle_table_lock);
			return DRM_INVALID_HANDLE;
		}
	}

	spin_unlock_preempt(&ctx->handle_table_lock);
	return handle;
}

drm_handle drm_add_object(struct drm_object *object, struct drm_device *dev)
{
	pid_t pid = get_current_process()->pid;

	struct drm_context *ctx = drm_get_context(pid, dev);

	assert(ctx != NULL);

	return __drm_add_object(ctx, object);
}

struct drm_object *__drm_get_object(struct drm_context *ctx, drm_handle handle)
{
	spin_lock(&ctx->handle_table_lock);

	if(handle >= ctx->handle_table_entries)
	{
		spin_unlock(&ctx->handle_table_lock);
		return NULL;
	}

	struct drm_object *object = ctx->handle_table[handle];
	spin_unlock(&ctx->handle_table_lock);

	return object;
}

struct drm_object *drm_get_object(drm_handle handle, struct drm_device *dev)
{
	pid_t pid = get_current_process()->pid;

	struct drm_context *ctx = drm_get_context(pid, dev);
	
	assert(ctx != NULL);

	return __drm_get_object(ctx, handle);
}

int drm_create_dumb_buffer(struct drm_dumb_buffer_info *buffer, struct drm_device *dev)
{
	assert(dev->d_ops.dumb_create != NULL);

	struct drm_dumb_buffer *buf = dev->d_ops.dumb_create(buffer, dev);
	if(!buf)
		return -1;
	
	drm_handle handle = drm_add_object(&buf->object, dev);
	if(handle == DRM_INVALID_HANDLE)
	{
		drm_object_release(&buf->object);
		return -1;
	}

	buffer->handle = handle;

	return 0;
}

int drm_on_open(struct inode *node)
{
	/* On open(), create a new process context
	 * if it doesn't exist already
	*/
	pid_t pid = get_current_process()->pid;

	if(drm_get_context(pid, main_device))
		return 0;
	
	return drm_create_process_context(pid, main_device);
}

int drm_swap_buffers(struct drm_swap_buffer_args *args, struct drm_device *dev)
{
	struct drm_object *obj = drm_get_object(args->buffer_handle, dev);

	if(!obj)
		return -EINVAL;
	
	if(!dev->d_ops.swap_buffers)
		return -EINVAL;

	return dev->d_ops.swap_buffers(obj, dev);
}

void __drm_append_mapping(struct drm_mapping *map, struct drm_context *c)
{
	spin_lock(&c->drm_mappings_lock);

	if(c->mappings == NULL)
	{
		c->mappings = map;
	}
	else
	{
		c->tail->next = map;
	}

	c->tail = map;
	spin_unlock(&c->drm_mappings_lock);
}

void drm_mapping_destroy(struct drm_object *object)
{
	struct drm_mapping *mapping = (struct drm_mapping *) object;
	drm_object_release(mapping->buffer);
}

off_t do_drm_enable_buffer_mappings(struct drm_object *obj, struct drm_device *dev)
{
	pid_t pid = get_current_process()->pid;

	struct drm_context *c = drm_get_context(pid, dev);
		
	struct drm_mapping *map = zalloc(sizeof(*map));
	if(!map)
		return -ENOMEM;
	drm_object_init(&map->object, drm_mapping_destroy, dev, DRM_COOKIE_MAPPING);
	drm_object_grab(obj);

	map->buffer = obj;
	map->fake_offset = atomic_fetch_add(&c->curr_fake_offset, PAGE_SIZE);

	__drm_append_mapping(map, c);

	return map->fake_offset;
}

off_t drm_enable_buffer_mappings(drm_handle handle, struct drm_device *dev)
{
	struct drm_object *obj = drm_get_object(handle, dev);

	if(!obj)
		return -EINVAL;

	if(obj->object_cookie != DRM_COOKIE_DUMB_BUFFER)
		return -EINVAL;

	off_t offset = do_drm_enable_buffer_mappings(obj, dev);

	return offset;
}

struct drm_mapping *do_drm_get_mapping(off_t offset, struct drm_context *c)
{
	spin_lock(&c->drm_mappings_lock);

	for(struct drm_mapping *m = c->mappings; m != NULL; m = m->next)
	{
		if(m->fake_offset == offset)
		{
			spin_unlock(&c->drm_mappings_lock);
			return m;
		}
	}

	spin_unlock(&c->drm_mappings_lock);
	return NULL;
}

struct drm_mapping *drm_get_mapping(off_t offset, struct drm_device *dev)
{
	pid_t pid = get_current_process()->pid;
	struct drm_context *context = drm_get_context(pid, dev);

	return do_drm_get_mapping(offset, context);
}

unsigned int drm_ioctl(int request, void *argp, struct inode* file)
{
	switch(request)
	{
		case DRM_IOCTL_CREATE_DUMB_BUF:
		{
			struct drm_dumb_buffer_info buf;
			if(copy_from_user(&buf, argp, sizeof(buf)) < 0)
				return -EFAULT;

			int st = drm_create_dumb_buffer(&buf, main_device);
			if(st < 0)
				return st;

			if(copy_to_user(argp, &buf, sizeof(buf)) < 0)
			{
				/* TODO: Close the handle */
				return -EFAULT;
			}

			return 0;
		}
		case DRM_IOCTL_SWAP_BUFS:
		{
			struct drm_swap_buffer_args a;
			if(copy_from_user(&a, argp, sizeof(a)) < 0)
				return -EFAULT;
			
			return drm_swap_buffers(&a, main_device);
		}
		case DRM_IOCTL_GET_VIDEOMODE:
		{
			struct drm_videomode mode;
			mode.width = main_device->fb->width;
			mode.height = main_device->fb->height;
			mode.bpp = main_device->fb->bpp;

			if(copy_to_user(argp, &mode, sizeof(mode)) < 0)
				return -EFAULT;
			return 0;
		}
		case DRM_IOCTL_CREATE_BUF_MAP:
		{
			struct drm_create_buf_map_args args;
			if(copy_from_user(&args, argp, sizeof(args)) < 0)
				return -EFAULT;
			
			off_t offset = 0;
			if((offset = drm_enable_buffer_mappings(args.handle, main_device)) < 0)
				return offset;
			
			return 0;
		}
	}

	return -EINVAL;
}

void drm_init_software_dev(void);

void *drm_mmap(struct vm_entry *area, struct inode *inode)
{
	struct drm_mapping *mapping = drm_get_mapping(area->offset, main_device);
	if(!mapping)
		return NULL;

	struct file_description *fd = zalloc(sizeof(*fd));

	if(!fd)
		return NULL;
	
	fd->vfs_node = inode;
	fd->seek = area->offset;
	
	struct drm_dumb_buffer *dbuf = (struct drm_dumb_buffer *) mapping->buffer;
	struct vm_object *vmo = vmo_create(dbuf->size, dbuf);

	if(!vmo)
		return NULL;

	vmo->page_list = dbuf->pages;
	vmo->mappings = area;
	vmo->u_info.fmap.fd = fd;
	vmo->u_info.fmap.off = 0;
	area->vmo = vmo;

	return (void *) area->base;
}

void drm_init(void)
{
	MPRINTF("Initializing the DRM subsystem\n");

	if(device_create_dir("drm") < 0)
	{
		perror("device_create_dir");
	}

	MPRINTF("Creating drm0\n");
	struct dev *dev = dev_register(0, 0, "drm0");
	if(!dev)
		return;

	dev->fops.on_open = drm_on_open;
	dev->fops.ioctl = drm_ioctl;
	dev->fops.mmap = drm_mmap;
	MPRINTF("drm0 devid %lx:%lx\n", MAJOR(dev->majorminor), MINOR(dev->majorminor));
	
	assert(device_show(dev, "drm") == 0);

	/* Create the backup software drm as the current device, so we always
	 * have a device that can create dumb buffers and swap fbs
	*/

	drm_init_software_dev();
}

void __drm_object_release(struct object *object)
{
	struct drm_object *obj = (struct drm_object *) object;
	if(obj->destroy) obj->destroy(obj);
}

void drm_object_init(struct drm_object *object,
	void (*destroy)(struct drm_object *object), struct drm_device *dev,
	unsigned long cookie)
{
	object_init(&object->object, __drm_object_release);
	object->destroy = destroy;
	object->device = dev;
	object->object_cookie = cookie;
}

void drm_object_grab(struct drm_object *object)
{
	object_ref(&object->object);
}

void drm_object_release(struct drm_object *object)
{
	object_unref(&object->object);
}