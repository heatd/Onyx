/*
 * Copyright (c) 2018 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <onyx/port_io.h>

#include <onyx/input/keys.h>
#include <onyx/input/event.h>
#include <onyx/panic.h>

#include "ps2.h"

unsigned int set1_keymap[] = 
{
	KEYMAP_NOT_MAPPED,
	KEYMAP_KEY_ESC,
	KEYMAP_KEY_1,
	KEYMAP_KEY_2,
	KEYMAP_KEY_3,
	KEYMAP_KEY_4,
	KEYMAP_KEY_5,
	KEYMAP_KEY_6,
	KEYMAP_KEY_7,
	KEYMAP_KEY_8,
	KEYMAP_KEY_9,
	KEYMAP_KEY_0,
	KEYMAP_KEY_MINUS,
	KEYMAP_KEY_EQUALS,
	KEYMAP_KEY_BACKSPACE,
	KEYMAP_KEY_TAB,
	KEYMAP_KEY_Q,
	KEYMAP_KEY_W,
	KEYMAP_KEY_E,
	KEYMAP_KEY_R,
	KEYMAP_KEY_T,
	KEYMAP_KEY_Y,
	KEYMAP_KEY_U,
	KEYMAP_KEY_I,
	KEYMAP_KEY_O,
	KEYMAP_KEY_P,
	KEYMAP_KEY_LEFTBRACE,
	KEYMAP_KEY_RIGHTBRACE,
	KEYMAP_KEY_ENTER,
	KEYMAP_KEY_LCTRL,
	KEYMAP_KEY_A,
	KEYMAP_KEY_S,
	KEYMAP_KEY_D,
	KEYMAP_KEY_F,
	KEYMAP_KEY_G,
	KEYMAP_KEY_H,
	KEYMAP_KEY_J,
	KEYMAP_KEY_K,
	KEYMAP_KEY_L,
	KEYMAP_KEY_SEMICOLON,
	KEYMAP_KEY_APOSTROPHE,
	KEYMAP_KEY_GRAVE,
	KEYMAP_KEY_LSHIFT,
	KEYMAP_KEY_BACKSLASH,
	KEYMAP_KEY_Z,
	KEYMAP_KEY_X,
	KEYMAP_KEY_C,
	KEYMAP_KEY_V,
	KEYMAP_KEY_B,
	KEYMAP_KEY_N,
	KEYMAP_KEY_M,
	KEYMAP_KEY_COMMA,
	KEYMAP_KEY_DOT,
	KEYMAP_KEY_SLASH,
	KEYMAP_KEY_RSHIFT,
	KEYMAP_KEY_KEYPAD_ASTERISK,
	KEYMAP_KEY_LALT,
	KEYMAP_KEY_SPACE,
	KEYMAP_KEY_CAPS_LOCK,
	KEYMAP_KEY_F1,
	KEYMAP_KEY_F2,
	KEYMAP_KEY_F3,
	KEYMAP_KEY_F4,
	KEYMAP_KEY_F5,
	KEYMAP_KEY_F6,
	KEYMAP_KEY_F7,
	KEYMAP_KEY_F8,
	KEYMAP_KEY_F9,
	KEYMAP_KEY_F10,
	KEYMAP_KEY_KEYPAD_NUMLCK,
	KEYMAP_KEY_KEYPAD_SCRLK,
	KEYMAP_KEY_KEYPAD_7,
	KEYMAP_KEY_KEYPAD_8,
	KEYMAP_KEY_KEYPAD_9,
	KEYMAP_KEY_KEYPAD_MINUS,
	KEYMAP_KEY_KEYPAD_4,
	KEYMAP_KEY_KEYPAD_5,
	KEYMAP_KEY_KEYPAD_6,
	KEYMAP_KEY_KEYPAD_PLUS,
	KEYMAP_KEY_KEYPAD_1,
	KEYMAP_KEY_KEYPAD_2,
	KEYMAP_KEY_KEYPAD_3,
	KEYMAP_KEY_KEYPAD_0,
	KEYMAP_KEY_KEYPAD_DOT,
	KEYMAP_NOT_MAPPED,
	KEYMAP_NOT_MAPPED,
	KEYMAP_102ND,
	KEYMAP_KEY_F11,
	KEYMAP_KEY_F12,
};

#define PS2_TWO_BYTE_CODE				0xe0

unsigned int ps2_keyb_get_two_byte_key(uint8_t bytes[2])
{
	uint8_t second_byte = bytes[1];

	switch(second_byte)
	{
		case 0x38:
			return KEYMAP_KEY_LALT;
		case 0x1d:
			return KEYMAP_KEY_RCTRL;
		case 0x52:
			return KEYMAP_KEY_INSERT;
		case 0x53:
			return KEYMAP_KEY_DEL;
		case 0x47:
			return KEYMAP_KEY_HOME;
		case 0x4f:
			return KEYMAP_KEY_END;
		case 0x49:
			return KEYMAP_KEY_PGUP;
		case 0x51:
			return KEYMAP_KEY_PGDN;
		case 0x4b:
			return KEYMAP_KEY_ARROW_LEFT;
		case 0x48:
			return KEYMAP_KEY_ARROW_UP;
		case 0x50:
			return KEYMAP_KEY_ARROW_DOWN;
		case 0x4d:
			return KEYMAP_KEY_ARROW_RIGHT;
		case 0x5b:
			return KEYMAP_KEY_WINKEY;
		case 0x5d:
			return KEYMAP_KEY_MENU;
		case 0x35:
			return KEYMAP_KEY_KEYPAD_SLASH;
		case 0x1c:
			return KEYMAP_KEY_KEYPAD_ENTER;
		case 0x37:
			return KEYMAP_KEY_PRTSC;
		default:
			return KEYMAP_NOT_MAPPED;
	}
}

#define PS2_PAUSE_BYTE			0xe1

void ps2_on_byte(struct ps2_port *port)
{
	unsigned int keycode;
	bool release;
	uint8_t bytes[2] = {};
	bytes[0] = ps2_read_data(port);

	if(bytes[0] == PS2_TWO_BYTE_CODE)
	{
		bytes[1] = ps2_read_data(port);
		release = bytes[1] & 0x80;
		bytes[1] &= ~0x80;
		keycode = ps2_keyb_get_two_byte_key(bytes);
	}
	else if(bytes[0] == PS2_PAUSE_BYTE)
	{
		/* We can discard these 5 bytes since the first one is unique */
		for(int i = 0; i < 5; i++)
			ps2_read_data(port);

		keycode = KEYMAP_KEY_PAUSE;
		release = true;
	}
	else
	{
		release = bytes[0] & 0x80;
		bytes[0] &= ~0x80;
		keycode = set1_keymap[bytes[0]];
	}

	if(keycode == KEYMAP_NOT_MAPPED)
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
		if(ps2_send_command_to_device(port, 0xf3, true, &response)
			== PS2_CMD_TIMEOUT)
			return;
		ps2_wait_for_input_buffer(port->controller);
		outb(port->controller->data_port, rate);

		ps2_wait_for_input_buffer(port->controller);
		response = inb(port->controller->data_port);
	} while(response == 0xfe);
}

void ps2_keyboard_init(struct ps2_port *port)
{
	port->on_byte = ps2_on_byte;

	ps2_set_typematic_rate(port);
	memset(&port->dev.state, 0, sizeof(struct input_state));
	input_device_register(&port->dev);
}
