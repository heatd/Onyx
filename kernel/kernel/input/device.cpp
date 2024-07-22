/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <stdlib.h>
#include <string.h>

#include <onyx/dev.h>
#include <onyx/dpc.h>
#include <onyx/input/device.h>
#include <onyx/input/event.h>
#include <onyx/panic.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>
#include <onyx/vfs.h>

#include <onyx/atomic.hpp>

static struct spinlock input_dev_list_lock;
static struct list_head input_dev_list = LIST_HEAD_INIT(input_dev_list);
static atomic<unsigned int> input_id = 0;

void input_device_register(input_device *dev)
{
    char new_name[64] = {};
    if (snprintf(new_name, 64, "input%u", input_id++) < 0)
        return;
    char *n = strdup(new_name);
    if (!n)
        panic("Out of memory strdup'ing name");
    dev->name = n;

    scoped_lock guard{input_dev_list_lock};
    list_add_tail(&dev->list, &input_dev_list);
}

void input_device_unregister(struct input_device *dev)
{
    scoped_lock guard{input_dev_list_lock};
    list_remove(&dev->list);
}

int vterm_submit_event(struct input_device *dev, struct input_event *ev);

void input_device_submit_event(struct input_device *dev, struct input_event *ev)
{
    bool pressed = ev->flags & INPUT_EVENT_FLAG_PRESSED;
    input_state_set_key_state(ev->code, pressed, &dev->state);

    /* TODO: Should this be vterm-specific code? GUI apps probably
     * just want the keypresses.
     */

    switch (ev->code)
    {
        case KEYMAP_KEY_LSHIFT:
        case KEYMAP_KEY_RSHIFT:
            dev->state.shift_pressed = pressed;
            break;
        case KEYMAP_KEY_CAPS_LOCK:
            dev->state.caps_enabled = !(dev->state.caps_enabled);
            break;
        case KEYMAP_KEY_LALT:
        case KEYMAP_KEY_ALTGR:
            dev->state.alt_pressed = pressed;
            break;
        case KEYMAP_KEY_LCTRL:
        case KEYMAP_KEY_RCTRL:
            dev->state.ctrl_pressed = pressed;
            break;
        default:
            break;
    }

    vterm_submit_event(dev, ev);
}
