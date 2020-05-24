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
#include <onyx/process.h>
#include <onyx/photon-cookies.h>
#include <onyx/init.h>

#include <photon/photon.h>

#define MPRINTF(...) printf("photon: " __VA_ARGS__)

#define PHOTON_NR_ENTRIES		1024

struct photon_device *main_device = NULL;

int photon_add_device(struct photon_device *device)
{
	/* TODO: This shouldn't be this simple, refactor this part of the code
	 * after writing a gpu driver.
	*/
	object_init(&device->object, NULL);
	INIT_LIST_HEAD(&device->named_list);

	main_device = device;

	return 0;
}

struct photon_context *photon_get_context(pid_t pid, struct photon_device *dev)
{
	spin_lock_preempt(&dev->context_lock);
	for(struct photon_context *c = dev->per_process_context; c != NULL; c = c->next)
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

int photon_create_process_context(pid_t pid, struct photon_device *device)
{
	struct photon_context *c = zalloc(sizeof(*c));
	if(!c)
		return -1;
	c->pid = pid;

	spin_lock_preempt(&device->context_lock);
	struct photon_context **pp = &device->per_process_context;

	while(*pp)
		pp = &(*pp)->next;

	*pp = c;

	spin_unlock_preempt(&device->context_lock);
	return 0;
}

int photon_expand_handle_table(struct photon_context *ctx)
{
	/* This executes with a lock held */

	size_t new_mem_index = ctx->handle_table_entries;
	ctx->handle_table_entries += PHOTON_NR_ENTRIES;
	struct photon_object **table = (struct photon_object **) realloc(ctx->handle_table,
		ctx->handle_table_entries * sizeof(struct photon_object *));

	if(!table)
	{
		ctx->handle_table_entries -= PHOTON_NR_ENTRIES;
		return -1;
	}

	memset(table + new_mem_index, 0, ctx->handle_table_entries - new_mem_index);

	ctx->handle_table = table;

	return 0;
}

photon_handle try_add_photon_object(struct photon_context *ctx, struct photon_object *object)
{
	for(size_t i = 0; i < ctx->handle_table_entries; i++)
	{
		if(ctx->handle_table[i] == NULL)
		{
			ctx->handle_table[i] = object;
			return i;
		}
	}

	return PHOTON_INVALID_HANDLE;
}

photon_handle __photon_add_object(struct photon_context *ctx, struct photon_object *object)
{
	spin_lock_preempt(&ctx->handle_table_lock);

	photon_handle handle = 0;

	while((handle = try_add_photon_object(ctx, object)) == PHOTON_INVALID_HANDLE)
	{
		if(photon_expand_handle_table(ctx) < 0)
		{
			spin_unlock_preempt(&ctx->handle_table_lock);
			return PHOTON_INVALID_HANDLE;
		}
	}

	spin_unlock_preempt(&ctx->handle_table_lock);
	return handle;
}

photon_handle photon_add_object(struct photon_object *object, struct photon_device *dev)
{
	pid_t pid = get_current_process()->pid;

	struct photon_context *ctx = photon_get_context(pid, dev);

	assert(ctx != NULL);

	return __photon_add_object(ctx, object);
}

struct photon_object *__photon_get_object(struct photon_context *ctx, photon_handle handle)
{
	spin_lock(&ctx->handle_table_lock);

	if(handle >= ctx->handle_table_entries)
	{
		spin_unlock(&ctx->handle_table_lock);
		return NULL;
	}

	struct photon_object *object = ctx->handle_table[handle];
	photon_object_grab(object);

	spin_unlock(&ctx->handle_table_lock);

	return object;
}

struct photon_object *photon_get_object(photon_handle handle, struct photon_device *dev)
{
	pid_t pid = get_current_process()->pid;

	struct photon_context *ctx = photon_get_context(pid, dev);
	
	assert(ctx != NULL);

	return __photon_get_object(ctx, handle);
}

unsigned int __photon_close_object(photon_handle handle, struct photon_context *ctx)
{
	spin_lock(&ctx->handle_table_lock);

	if(handle >= ctx->handle_table_entries)
	{
		spin_unlock(&ctx->handle_table_lock);
		return -EINVAL;
	}

	struct photon_object *object = ctx->handle_table[handle];
	photon_object_release(object);
	ctx->handle_table[handle] = NULL;

	spin_unlock(&ctx->handle_table_lock);

	return 0;
}

unsigned int photon_close_object(photon_handle handle, struct photon_device *dev)
{
	pid_t pid = get_current_process()->pid;

	struct photon_context *ctx = photon_get_context(pid, dev);
	
	assert(ctx != NULL);

	return __photon_close_object(handle, ctx);
}

void photon_remove_from_named_list(struct photon_object *obj)
{
	spin_lock(&obj->device->named_list_lock);

	list_remove(&obj->named_list);

	spin_unlock(&obj->device->named_list_lock);

	obj->flags &= ~PHOTON_OBJECT_NAMED;
	obj->security_cookie = UINT64_MAX;
}

int photon_create_dumb_buffer(struct photon_dumb_buffer_info *buffer, struct photon_device *dev)
{
	assert(dev->d_ops.dumb_create != NULL);

	struct photon_dumb_buffer *buf = dev->d_ops.dumb_create(buffer, dev);
	if(!buf)
		return -ENOMEM;

	photon_handle handle = photon_add_object(&buf->object, dev);
	if(handle == PHOTON_INVALID_HANDLE)
	{
		photon_object_release(&buf->object);
		return -ENOMEM;
	}

	//printk("Created photon buffer handle %lu %p\n", handle, buf);

	buffer->handle = handle;

	return 0;
}

int photon_on_open(struct file *node)
{
	/* On open(), create a new process context
	 * if it doesn't exist already
	*/
	pid_t pid = get_current_process()->pid;

	if(photon_get_context(pid, main_device))
		return 0;
	
	return photon_create_process_context(pid, main_device);
}

int photon_swap_buffers(struct photon_swap_buffer_args *args, struct photon_device *dev)
{
	if(!dev->d_ops.swap_buffers)
		return -EINVAL;

	struct photon_object *obj = photon_get_object(args->buffer_handle, dev);

	if(!obj)
		return -EINVAL;

	int ret = dev->d_ops.swap_buffers(obj, dev);

	photon_object_release(obj);

	return ret;
}

void __photon_append_mapping(struct photon_mapping *map, struct photon_context *c)
{
	spin_lock(&c->photon_mappings_lock);

	if(c->mappings == NULL)
	{
		c->mappings = map;
	}
	else
	{
		c->tail->next = map;
	}

	c->tail = map;
	spin_unlock(&c->photon_mappings_lock);
}

void photon_mapping_destroy(struct photon_object *object)
{
	struct photon_mapping *mapping = (struct photon_mapping *) object;
	photon_object_release(mapping->buffer);
}

off_t do_photon_enable_buffer_mappings(struct photon_object *obj, struct photon_device *dev)
{
	pid_t pid = get_current_process()->pid;

	struct photon_context *c = photon_get_context(pid, dev);
		
	struct photon_mapping *map = zalloc(sizeof(*map));
	if(!map)
		return -ENOMEM;
	
	photon_object_init(&map->object, photon_mapping_destroy, dev, PHOTON_COOKIE_MAPPING);

	map->buffer = obj;
	map->fake_offset = atomic_fetch_add(&c->curr_fake_offset, PAGE_SIZE);

	__photon_append_mapping(map, c);

	return map->fake_offset;
}

off_t photon_enable_buffer_mappings(photon_handle handle, struct photon_device *dev)
{
	struct photon_object *obj = photon_get_object(handle, dev);

	if(!obj)
		return -EINVAL;

	if(obj->object_cookie != PHOTON_COOKIE_DUMB_BUFFER)
	{
		photon_object_release(obj);
		return -EINVAL;
	}

	off_t offset = do_photon_enable_buffer_mappings(obj, dev);

	return offset;
}

struct photon_mapping *do_photon_get_mapping(off_t offset, struct photon_context *c)
{
	spin_lock(&c->photon_mappings_lock);

	for(struct photon_mapping *m = c->mappings; m != NULL; m = m->next)
	{
		if(m->fake_offset == offset)
		{
			spin_unlock(&c->photon_mappings_lock);
			return m;
		}
	}

	spin_unlock(&c->photon_mappings_lock);
	return NULL;
}

struct photon_mapping *photon_get_mapping(off_t offset, struct photon_device *dev)
{
	pid_t pid = get_current_process()->pid;
	struct photon_context *context = photon_get_context(pid, dev);

	return do_photon_get_mapping(offset, context);
}

bool photon_generate_name(struct photon_device *dev, uint32_t *name)
{
	/* TODO: Eventually we'll hit the max of names even if they're all closed.
	 * What should we do?
	*/
	uint32_t next_name;
	uint32_t expected;
	do
	{
		expected = dev->current_name;
		next_name = expected + 1;
		/* If we overflowed, we ran out of names, so just return an error */
		if(next_name == 0)
			return false;
	} while(!atomic_compare_exchange_strong(&dev->current_name, &expected, next_name));
	
	*name = expected;

	return true;
}

unsigned int photon_ioctl_set_name(struct photon_set_name_args *uargs, struct photon_device *dev)
{
	struct photon_set_name_args kargs;
	if(copy_from_user(&kargs, uargs, sizeof(kargs)) < 0)
		return -EFAULT;

	struct photon_object *obj = photon_get_object(kargs.handle, dev);
	if(!obj)
		return -EINVAL;

	uint32_t name;
	if(!photon_generate_name(dev, &name))
	{
		photon_object_release(obj);
		return -ERANGE;
	}
	
	obj->flags |= PHOTON_OBJECT_NAMED;
	obj->security_cookie = kargs.security_cookie;
	obj->name = name;

	kargs.name = name;
	if(copy_to_user(uargs, &kargs, sizeof(kargs)) < 0)
	{
		obj->flags &= ~PHOTON_OBJECT_NAMED;
		obj->security_cookie = UINT64_MAX;
		obj->name = 0;
		photon_object_release(obj);
		return -EFAULT;
	}

	spin_lock(&dev->named_list_lock);

	list_add(&obj->named_list, &dev->named_list);
	
	spin_unlock(&dev->named_list_lock);

	return 0;
}

struct photon_object *photon_get_object_from_name(uint32_t name, struct photon_device *dev)
{
	spin_lock(&dev->named_list_lock);

	list_for_every(&dev->named_list)
	{
		struct photon_object *obj = container_of(l, struct photon_object, named_list);
		if(obj->name == name)
		{
			photon_object_grab(obj);
			spin_unlock(&dev->named_list_lock);
			return obj;
		}
	}

	spin_unlock(&dev->named_list_lock);

	return NULL;
}

unsigned int photon_ioctl_open_from_name(struct photon_open_from_name_args *uargs, struct photon_device *dev)
{
	struct photon_open_from_name_args kargs;
	if(copy_from_user(&kargs, uargs, sizeof(kargs)) < 0)
		return -EFAULT;
	
	struct photon_object *obj = photon_get_object_from_name(kargs.name, dev);
	if(!obj)
		return -EINVAL;
	
	if(obj->security_cookie != kargs.security_cookie)
		return -EINVAL;
	
	photon_handle h = photon_add_object(obj, dev);

	if(h == PHOTON_INVALID_HANDLE)
	{
		photon_object_release(obj);
		return -ENOMEM;
	}

	kargs.handle = h;

	if(copy_to_user(uargs, &kargs, sizeof(kargs)) < 0)
		return -EFAULT;
	return 0;
}

unsigned int photon_ioctl_close_handle(struct photon_close_handle_args *uargs, struct photon_device *dev)
{
	struct photon_close_handle_args kargs;
	if(copy_from_user(&kargs, uargs, sizeof(kargs)) < 0)
		return -EFAULT;

	return photon_close_object(kargs.handle, dev);
}

unsigned int photon_ioctl(int request, void *argp, struct file *file)
{
	switch(request)
	{
		case PHOTON_IOCTL_CREATE_DUMB_BUF:
		{
			struct photon_dumb_buffer_info buf;
			if(copy_from_user(&buf, argp, sizeof(buf)) < 0)
				return -EFAULT;

			int st = photon_create_dumb_buffer(&buf, main_device);
			if(st < 0)
				return st;

			if(copy_to_user(argp, &buf, sizeof(buf)) < 0)
			{
				photon_close_object(buf.handle, main_device);
				return -EFAULT;
			}

			return 0;
		}
		case PHOTON_IOCTL_SWAP_BUFS:
		{
			struct photon_swap_buffer_args a;
			if(copy_from_user(&a, argp, sizeof(a)) < 0)
				return -EFAULT;
			
			return photon_swap_buffers(&a, main_device);
		}
		case PHOTON_IOCTL_GET_VIDEOMODE:
		{
			struct photon_videomode mode;
			mode.width = main_device->fb->width;
			mode.height = main_device->fb->height;
			mode.bpp = main_device->fb->bpp;

			if(copy_to_user(argp, &mode, sizeof(mode)) < 0)
				return -EFAULT;
			return 0;
		}
		case PHOTON_IOCTL_CREATE_BUF_MAP:
		{
			struct photon_create_buf_map_args args;
			if(copy_from_user(&args, argp, sizeof(args)) < 0)
				return -EFAULT;
			
			off_t offset = 0;
			if((offset = photon_enable_buffer_mappings(args.handle, main_device)) < 0)
				return offset;
			args.offset = offset;
			if(copy_to_user(argp, &args, sizeof(args)) < 0)
				return -EFAULT;
			return 0;
		}
		case PHOTON_IOCTL_SET_NAME:
			return photon_ioctl_set_name((struct photon_set_name_args *) argp, main_device);
		case PHOTON_IOCTL_OPEN_FROM_NAME:
			return photon_ioctl_open_from_name((struct photon_open_from_name_args *) argp, main_device);
		case PHOTON_IOCTL_CLOSE_OBJECT:
			return photon_ioctl_close_handle((struct photon_close_handle_args *) argp, main_device);
	}

	return -EINVAL;
}

void photon_init_software_dev(void);

void *photon_mmap(struct vm_region *area, struct file *f)
{
	struct photon_mapping *mapping = photon_get_mapping(area->offset, main_device);
	if(!mapping)
		return NULL;
	//printk("mapping object %p\n", mapping->buffer);

	struct file *fd = zalloc(sizeof(*fd));

	if(!fd)
		return NULL;
	
	fd->f_ino = f->f_ino;
	object_ref(&f->f_ino->i_object);
	area->offset = 0;

	struct photon_dumb_buffer *dbuf = (struct photon_dumb_buffer *) mapping->buffer;
	struct vm_object *vmo = vmo_create(dbuf->size, dbuf);

	if(!vmo)
		return NULL;

	size_t nr_pages = vm_size_to_pages(dbuf->size);
	struct page *p = dbuf->pages;
	size_t off = 0;
	while(nr_pages--)
	{
		if(vmo_add_page(off, p, vmo) < 0)
		{
			vmo_destroy(vmo);
			return NULL;
		}

		p = p->next_un.next_allocation;
		off += PAGE_SIZE;
	}

	vmo_assign_mapping(vmo, area);

	vmo->ino = f->f_ino;
	vmo->flags |= VMO_FLAG_DEVICE_MAPPING;

	area->vmo = vmo;

	return (void *) area->base;
}

void photon_init(void)
{
	MPRINTF("Initializing the photon subsystem\n");

	if(device_create_dir("photon") < 0)
	{
		perror("device_create_dir");
	}

	MPRINTF("Creating photon0\n");
	struct dev *dev = dev_register(0, 0, "photon0");
	if(!dev)
		return;

	dev->fops.on_open = photon_on_open;
	dev->fops.ioctl = photon_ioctl;
	dev->fops.mmap = photon_mmap;
	MPRINTF("photon0 devid %lx:%lx\n", MAJOR(dev->majorminor), MINOR(dev->majorminor));
	
	assert(device_show(dev, "photon", 0666) == 0);

	/* Create the backup software photon as the current device, so we always
	 * have a device that can create dumb buffers and swap fbs
	*/

	photon_init_software_dev();
}

INIT_LEVEL_CORE_KERNEL_ENTRY(photon_init);

void __photon_object_release(struct object *object)
{
	struct photon_object *obj = (struct photon_object *) object;

	if(obj->flags & PHOTON_OBJECT_NAMED)
	{
		photon_remove_from_named_list(obj);
	}

	if(obj->destroy) obj->destroy(obj);
}

void photon_object_init(struct photon_object *object,
	void (*destroy)(struct photon_object *object), struct photon_device *dev,
	unsigned long cookie)
{
	object_init(&object->object, __photon_object_release);
	object->destroy = destroy;
	object->device = dev;
	object->object_cookie = cookie;
}

void photon_object_grab(struct photon_object *object)
{
	object_ref(&object->object);
}

void photon_object_release(struct photon_object *object)
{
	object_unref(&object->object);
}
