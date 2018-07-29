/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_DRM_H
#define _ONYX_DRM_H

#include <onyx/object.h>
#include <onyx/framebuffer.h>
#include <onyx/spinlock.h>

#include <drm/drm.h>

struct drm_device;

struct drm_object
{
	struct object object;
	struct drm_device *device;
	unsigned long object_cookie;
	void (*destroy)(struct drm_object *object);
};

struct drm_dumb_buffer
{
	struct drm_object object;
	void *buffer;
	struct page *pages;
	uint32_t size;
};

struct drm_ops
{
	struct drm_dumb_buffer *(*dumb_create)(struct drm_dumb_buffer_info
		*buffer, struct drm_device *dev);
	int (*modeset)(struct drm_modeset_args *args, struct drm_device *dev);
	int (*swap_buffers)(struct drm_object *buffer, struct drm_device *dev);
};

struct drm_mapping
{
	struct drm_object object;
	off_t fake_offset;
	struct drm_object *buffer;
	struct drm_mapping *next;
};

struct drm_context
{
	pid_t pid;
	size_t handle_table_entries;
	struct drm_object **handle_table;
	struct spinlock handle_table_lock;
	off_t curr_fake_offset;
	struct drm_mapping *mappings;
	struct drm_mapping *tail;
	struct spinlock drm_mappings_lock;
	struct drm_context *next;
};

struct drm_device
{
	struct object object;
	const char *name;
	struct dev *dev;
	const char *driver_info;
	struct framebuffer *fb;
	struct drm_ops d_ops;

	struct spinlock context_lock;
	struct drm_context *per_process_context;
};


void drm_init(void);
int drm_add_device(struct drm_device *device);
void drm_object_init(struct drm_object *object,
	void (*destroy)(struct drm_object *object), struct drm_device *dev,
	unsigned long cookie);
void drm_object_grab(struct drm_object *object);
void drm_object_release(struct drm_object *object);

#endif