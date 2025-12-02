/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <stdlib.h>
#include <string.h>

#include <onyx/dev.h>
#include <onyx/dpc.h>
#include <onyx/input-event-codes.h>
#include <onyx/input/device.h>
#include <onyx/input/event.h>
#include <onyx/panic.h>
#include <onyx/scoped_lock.h>
#include <onyx/spinlock.h>
#include <onyx/vfs.h>

#include <onyx/atomic.hpp>

static DEFINE_SPINLOCK(input_dev_list_lock);
static struct list_head input_dev_list = LIST_HEAD_INIT(input_dev_list);
static atomic<unsigned int> input_id = 0;

extern "C" struct file_ops evdev_fops;

void input_device_register(struct input_device *dev)
{
    char new_name[64] = {};
    if (snprintf(new_name, 64, "event%u", input_id++) < 0)
        return;
    char *n = strdup(new_name);
    if (!n)
        panic("Out of memory strdup'ing name");
    dev->name = n;
    INIT_LIST_HEAD(&dev->client_list);
    spinlock_init(&dev->client_list_lock);
    memset(&dev->leds, 0, sizeof(dev->leds));
    memset(&dev->switch_bits, 0, sizeof(dev->switch_bits));

    auto ex = dev_register_chardevs(0, 1, 0, &evdev_fops, n);
    auto cdev = ex.unwrap();
    cdev->private_ = dev;
    cdev->show_with_name(new_name, "input/", 0660);
    scoped_lock guard{input_dev_list_lock};
    list_add_tail(&dev->list, &input_dev_list);
}

void input_device_unregister(struct input_device *dev)
{
    scoped_lock guard{input_dev_list_lock};
    list_remove(&dev->list);
}

extern "C" void evdev_submit_event(struct input_device *dev, struct evdev_input_event *ev);

int vterm_submit_event(struct input_device *dev, struct input_event *ev);

#define TIMESPEC_TO_TIMEVAL(tv, ts) \
    ((tv)->tv_sec = (ts)->tv_sec, (tv)->tv_usec = (ts)->tv_nsec / 1000, (void) 0)

void input_device_submit_event(struct input_device *dev, struct input_event *ev)
{
    struct evdev_input_event evdev_ev = {};
    struct timespec ts;
    bool pressed = ev->flags & INPUT_EVENT_FLAG_PRESSED;

    evdev_ev.code = ev->code;
    evdev_ev.type = EV_KEY;
    evdev_ev.value = pressed ? 1 : 0;
    clock_gettime_kernel(CLOCK_REALTIME, &ts);
    TIMESPEC_TO_TIMEVAL(&evdev_ev.time, &ts);
    evdev_submit_event(dev, &evdev_ev);
    evdev_ev.code = SYN_REPORT;
    evdev_ev.type = EV_SYN;
    evdev_ev.value = 1;
    evdev_submit_event(dev, &evdev_ev);
    /* TODO: Should this be vterm-specific code? GUI apps probably
     * just want the keypresses.
     */

    input_state_set_key_state(ev->code, pressed, &dev->state);
    switch (ev->code)
    {
        case KEY_LEFTSHIFT:
        case KEY_RIGHTSHIFT:
            dev->state.shift_pressed = pressed;
            break;
        case KEY_CAPSLOCK:
            dev->state.caps_enabled = !(dev->state.caps_enabled);
            break;
        case KEY_LEFTALT:
        case KEY_RIGHTALT:
            dev->state.alt_pressed = pressed;
            break;
        case KEY_LEFTCTRL:
        case KEY_RIGHTCTRL:
            dev->state.ctrl_pressed = pressed;
            break;
        default:
            break;
    }

    /* vterm will not look at this event. */
    if (rcu_access_pointer(dev->grab))
        return;

    vterm_submit_event(dev, ev);
}
