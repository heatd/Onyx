/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>

#include <onyx/input-event-codes.h>
#include <onyx/input/event.h>
#include <onyx/input/keys.h>
#include <onyx/panic.h>
#include <onyx/port_io.h>

#include "ps2.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define PS2_MOUSE_LEFT   (1 << 0)
#define PS2_MOUSE_RIGHT  (1 << 1)
#define PS2_MOUSE_MIDDLE (1 << 2)
#define PS2_MOUSE_YSIGN  (1 << 5)
#define PS2_MOUSE_XSIGN  (1 << 4)

extern "C" void evdev_submit_event(struct input_device *dev, struct evdev_input_event *ev);

#define TIMESPEC_TO_TIMEVAL(tv, ts) \
    ((tv)->tv_sec = (ts)->tv_sec, (tv)->tv_usec = (ts)->tv_nsec / 1000, (void) 0)

static void ps2_on_byte(struct ps2_port *port)
{
    struct evdev_input_event evdev_ev = {};
    struct input_event ev;
    uint8_t bytes[4] = {};
    struct timespec ts;
    int x, y;

    bytes[0] = ps2_read_data(port);
    bytes[1] = ps2_read_data(port);
    bytes[2] = ps2_read_data(port);

    x = bytes[1] ? bytes[1] - ((bytes[0] << 4) & 0x100) : 0;
    y = bytes[2] ? bytes[2] - ((bytes[0] << 3) & 0x100) : 0;

    evdev_ev.code = REL_Y;
    evdev_ev.type = EV_REL;
    evdev_ev.value = -y;
    clock_gettime_kernel(CLOCK_REALTIME, &ts);
    TIMESPEC_TO_TIMEVAL(&evdev_ev.time, &ts);
    evdev_submit_event(&port->dev, &evdev_ev);
    evdev_ev.code = REL_X;
    evdev_ev.type = EV_REL;
    evdev_ev.value = x;
    evdev_submit_event(&port->dev, &evdev_ev);
    evdev_ev.code = SYN_REPORT;
    evdev_ev.type = EV_SYN;
    evdev_ev.value = 1;
    evdev_submit_event(&port->dev, &evdev_ev);
    ev.type = INPUT_EVENT_TYPE_KEYBOARD;
    ev.code = (keycode_t) BTN_LEFT;
    ev.flags = (bytes[0] & PS2_MOUSE_LEFT);
    input_device_submit_event(&port->dev, &ev);
    ev.code = (keycode_t) BTN_RIGHT;
    ev.flags = (bytes[0] & PS2_MOUSE_RIGHT);
    input_device_submit_event(&port->dev, &ev);
    ev.code = (keycode_t) BTN_MIDDLE;
    ev.flags = (bytes[0] & PS2_MOUSE_MIDDLE);
    input_device_submit_event(&port->dev, &ev);
}

int ps2_reset_device(struct ps2_port *port);

static void ps2_enable_mouse(struct ps2_port *port)
{
    uint8_t response = 0;

    ps2_reset_device(port);

    do
    {
        if (ps2_send_command_to_device(port, 0xf4, true, &response) == PS2_CMD_TIMEOUT)
            return;
    } while (response == 0xfe);
}

void ps2_mouse_init(struct ps2_port *port)
{
    struct input_device *dev = &port->dev;

    port->on_byte = ps2_on_byte;

    ps2_enable_mouse(port);
    memset(&port->dev.state, 0, sizeof(struct input_state));
    dev->input_id.bustype = BUS_I8042;
    dev->input_id.product = 1;
    dev->input_id.vendor = 1;
    dev->input_id.version = 1;
    dev->feature_bits = (1UL << EV_SYN) | (1UL << EV_KEY) | (1UL << EV_REL);

    memset(&dev->properties, 0, sizeof(dev->properties));
    dev->grab = NULL;
    dev->phys = "isa0060/serio0";
    input_add_key(&port->dev, BTN_LEFT);
    input_add_key(&port->dev, BTN_RIGHT);
    input_add_key(&port->dev, BTN_MIDDLE);
    input_device_register(&port->dev);
}
