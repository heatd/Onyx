/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_INPUT_DEVICE_H
#define _ONYX_INPUT_DEVICE_H

#include <onyx/input-event-codes.h>
#include <onyx/input/state.h>
#include <onyx/list.h>
#include <onyx/rcupdate.h>
#include <onyx/spinlock.h>
#include <onyx/wait_queue.h>

#include <uapi/evdev.h>
#include <uapi/time_types.h>

struct input_device
{
    const char *name;
    const char *phys;
    struct input_state state;
    struct list_head list;
    struct spinlock client_list_lock;
    struct list_head client_list;
    struct input_id input_id;
    unsigned long feature_bits;
    unsigned long key_bits[BITS_TO_LONGS(KEY_CNT)];
    unsigned long properties[BITS_TO_LONGS(INPUT_PROP_CNT)];
    struct evdev_client __rcu *grab;
};

static inline void input_add_key(struct input_device *dev, unsigned int key)
{
    dev->key_bits[key / BITS_PER_LONG] |= (1UL << (key % BITS_PER_LONG));
}

struct evdev_input_event
{
    struct timeval time;
    unsigned short type;
    unsigned short code;
    int value;
};

struct evdev_client
{
    struct evdev_input_event *buffer;
    u32 write;
    u32 read;
    u32 buf_size;
    struct spinlock buffer_lock;
    struct input_device *dev;
    struct rcu_head rcu_head;
    struct list_head node;
    struct wait_queue wq;
};

__BEGIN_CDECLS
struct input_event;

void input_device_register(struct input_device *dev);
void input_device_unregister(struct input_device *dev);
void input_device_submit_event(struct input_device *dev, struct input_event *ev);

__END_CDECLS

#endif
