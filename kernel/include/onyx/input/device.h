/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_INPUT_DEVICE_H
#define _ONYX_INPUT_DEVICE_H

#include <onyx/list.h>

#include <onyx/input/state.h>

struct input_device
{
	const char *name;
	struct inode *devfs_inode;
	struct input_state state;
	struct list_head list;
};

struct input_event;

void input_device_register(struct input_device *dev);
void input_device_unregister(struct input_device *dev);
void input_device_submit_event(struct input_device *dev, struct input_event *ev);

#endif
