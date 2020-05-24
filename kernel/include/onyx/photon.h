/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PHOTON_H
#define _ONYX_PHOTON_H

#include <onyx/object.h>
#include <onyx/framebuffer.h>
#include <onyx/spinlock.h>

#include <photon/photon.h>

struct photon_device;

#define PHOTON_OBJECT_NAMED               (1 << 0)

struct photon_object
{
	struct object object;
	struct photon_device *device;
	unsigned long object_cookie;
	unsigned long flags;
	uint32_t name;
	/* Security cookie set by user space as to disallow access by random processes */
	/* TODO: Maybe this isn't safe? It's 64-bit now so it should be relatively safe from
	 * bruteforce but I don't think it's the right approach */
	uint64_t security_cookie;
	struct list_head named_list;
	void (*destroy)(struct photon_object *object);
};

struct photon_dumb_buffer
{
	struct photon_object object;
	void *buffer;
	struct page *pages;
	uint32_t size;
};

struct photon_ops
{
	struct photon_dumb_buffer *(*dumb_create)(struct photon_dumb_buffer_info
		*buffer, struct photon_device *dev);
	int (*modeset)(struct photon_modeset_args *args, struct photon_device *dev);
	int (*swap_buffers)(struct photon_object *buffer, struct photon_device *dev);
};

struct photon_mapping
{
	struct photon_object object;
	off_t fake_offset;
	struct photon_object *buffer;
	struct photon_mapping *next;
};

struct photon_context
{
	pid_t pid;
	size_t handle_table_entries;
	struct photon_object **handle_table;
	struct spinlock handle_table_lock;
	off_t curr_fake_offset;
	struct photon_mapping *mappings;
	struct photon_mapping *tail;
	struct spinlock photon_mappings_lock;
	struct photon_context *next;
};

struct photon_device
{
	struct object object;
	const char *name;
	struct dev *dev;
	const char *driver_info;
	struct framebuffer *fb;
	struct photon_ops d_ops;

	struct spinlock named_list_lock;
	struct list_head named_list;
	uint32_t current_name;

	struct spinlock context_lock;
	struct photon_context *per_process_context;
};


void photon_init(void);
int photon_add_device(struct photon_device *device);
void photon_object_init(struct photon_object *object,
	void (*destroy)(struct photon_object *object), struct photon_device *dev,
	unsigned long cookie);
void photon_object_grab(struct photon_object *object);
void photon_object_release(struct photon_object *object);

#endif
