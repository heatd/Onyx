/*
 * Copyright (c) 2018 - 2026 Pedro Falcato
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

// clang-format off
static unsigned int set1_keymap[] = {
    KEY_RESERVED,
    KEY_ESC,
    KEY_1,
    KEY_2,
    KEY_3,
    KEY_4,
    KEY_5,
    KEY_6,
    KEY_7,
    KEY_8,
    KEY_9,
    KEY_0,
    KEY_MINUS,
    KEY_EQUAL,
    KEY_BACKSPACE,
    KEY_TAB,
    KEY_Q,
    KEY_W,
    KEY_E,
    KEY_R,
    KEY_T,
    KEY_Y,
    KEY_U,
    KEY_I,
    KEY_O,
    KEY_P,
    KEY_LEFTBRACE,
    KEY_RIGHTBRACE,
    KEY_ENTER,
    KEY_LEFTCTRL,
    KEY_A,
    KEY_S,
    KEY_D,
    KEY_F,
    KEY_G,
    KEY_H,
    KEY_J,
    KEY_K,
    KEY_L,
    KEY_SEMICOLON,
    KEY_APOSTROPHE,
    KEY_GRAVE,
    KEY_LEFTSHIFT,
    KEY_BACKSLASH,
    KEY_Z,
    KEY_X,
    KEY_C,
    KEY_V,
    KEY_B,
    KEY_N,
    KEY_M,
    KEY_COMMA,
    KEY_DOT,
    KEY_SLASH,
    KEY_RIGHTSHIFT,
    KEY_KPASTERISK,
    KEY_LEFTALT,
    KEY_SPACE,
    KEY_CAPSLOCK,
    KEY_F1,
    KEY_F2,
    KEY_F3,
    KEY_F4,
    KEY_F5,
    KEY_F6,
    KEY_F7,
    KEY_F8,
    KEY_F9,
    KEY_F10,
    KEY_NUMLOCK,
    KEY_SCROLLLOCK,
    KEY_KP7,
    KEY_KP8,
    KEY_KP9,
    KEY_KPMINUS,
    KEY_KP4,
    KEY_KP5,
    KEY_KP6,
    KEY_KPPLUS,
    KEY_KP1,
    KEY_KP2,
    KEY_KP3,
    KEY_KP0,
    KEY_KPDOT,
    KEY_RESERVED,
    KEY_RESERVED,
    KEY_102ND,
    KEY_F11,
    KEY_F12,
};

// clang-format on

static unsigned int two_bytes[] = {
    KEY_LEFTALT,  KEY_RIGHTCTRL, KEY_INSERT,  KEY_DELETE,  KEY_HOME,  KEY_END,
    KEY_PAGEUP,   KEY_PAGEDOWN,  KEY_LEFT,    KEY_UP,      KEY_DOWN,  KEY_RIGHT,
    KEY_LEFTMETA, KEY_MENU,      KEY_KPSLASH, KEY_KPENTER, KEY_SYSRQ,
};

#define PS2_TWO_BYTE_CODE 0xe0

unsigned int ps2_keyb_get_two_byte_key(uint8_t bytes[2])
{
    uint8_t second_byte = bytes[1];

    switch (second_byte)
    {
        case 0x38:
            return KEY_LEFTALT;
        case 0x1d:
            return KEY_RIGHTCTRL;
        case 0x52:
            return KEY_INSERT;
        case 0x53:
            return KEY_DELETE;
        case 0x47:
            return KEY_HOME;
        case 0x4f:
            return KEY_END;
        case 0x49:
            return KEY_PAGEUP;
        case 0x51:
            return KEY_PAGEDOWN;
        case 0x4b:
            return KEY_LEFT;
        case 0x48:
            return KEY_UP;
        case 0x50:
            return KEY_DOWN;
        case 0x4d:
            return KEY_RIGHT;
        case 0x5b:
            return KEY_LEFTMETA;
        case 0x5d:
            return KEY_MENU;
        case 0x35:
            return KEY_KPSLASH;
        case 0x1c:
            return KEY_KPENTER;
        case 0x37:
            return KEY_SYSRQ;
        default:
            return KEY_RESERVED;
    }
}

#define PS2_PAUSE_BYTE 0xe1

void ps2_on_byte(struct ps2_port *port)
{
    unsigned int keycode;
    bool release;
    uint8_t bytes[2] = {};
    bytes[0] = ps2_read_data(port);

    if (bytes[0] == PS2_TWO_BYTE_CODE)
    {
        bytes[1] = ps2_read_data(port);
        release = bytes[1] & 0x80;
        bytes[1] &= ~0x80;
        keycode = ps2_keyb_get_two_byte_key(bytes);
    }
    else if (bytes[0] == PS2_PAUSE_BYTE)
    {
        /* We can discard these 5 bytes since the first one is unique */
        for (int i = 0; i < 5; i++)
            ps2_read_data(port);

        keycode = KEY_PAUSE;
        release = true;
    }
    else
    {
        release = bytes[0] & 0x80;
        bytes[0] &= ~0x80;
        keycode = set1_keymap[bytes[0]];
    }

    if (keycode == KEY_RESERVED)
    {
#if CONFIG_DEBUG_KEYBOARD_PANIC_ON_UNKNOWN
        panic("BUG: keycode %u not mapped!\n", keycode);
#endif
        return;
    }

    struct input_event ev;
    ev.code = (keycode_t) keycode;
    ev.flags = (!release ? INPUT_EVENT_FLAG_PRESSED : 0);
    ev.type = INPUT_EVENT_TYPE_KEYBOARD;

    input_device_submit_event(&port->dev, &ev);
}

void ps2_set_typematic_rate(struct ps2_port *port)
{
    uint8_t rate = 0 | (1 << 5);
    uint8_t response = 0;

    do
    {
        if (ps2_send_command_to_device(port, 0xf3, true, &response) == PS2_CMD_TIMEOUT)
            return;
        if (ps2_send_command_to_device(port, rate, true, &response) == PS2_CMD_TIMEOUT)
            return;
    } while (response == 0xfe);
}

void ps2_keyboard_init(struct ps2_port *port)
{
    struct input_device *dev = &port->dev;

    port->on_byte = ps2_on_byte;

    ps2_set_typematic_rate(port);
    memset(&port->dev.state, 0, sizeof(struct input_state));
    dev->input_id.bustype = BUS_I8042;
    dev->input_id.product = 1;
    dev->input_id.vendor = 1;
    dev->input_id.version = 1;
    dev->feature_bits = (1UL << EV_SYN) | (1UL << EV_KEY);

    for (unsigned int i = 0; i < ARRAY_SIZE(set1_keymap); i++)
    {
        if (set1_keymap[i] == KEY_RESERVED)
            continue;
        input_add_key(dev, set1_keymap[i]);
    }

    for (unsigned int i = 0; i < ARRAY_SIZE(two_bytes); i++)
        input_add_key(dev, two_bytes[i]);
    memset(&dev->properties, 0, sizeof(dev->properties));
    dev->grab = NULL;
    dev->phys = "isa0060/serio0";
    input_device_register(&port->dev);
}
