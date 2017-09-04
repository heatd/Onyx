/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/**************************************************************************
 *
 *
 * File: input_manager.c
 *
 * Description: Recieves keyboard presses, and translates them to keyboard events
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <onyx/compiler.h>
#include <onyx/log.h>
#include <onyx/tty.h>
#include <onyx/irq.h>
#include <onyx/keys.h>
unsigned int default_keymap[200] =
{ 
	KEYMAP_KEY_ESC, '1', '2', '3', '4', '5',
	 '6', '7', '8', '9', '0', '-', '=', '\b', '\t',
	'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',
	 'o', 'p', '[', ']', '\n', KEYMAP_KEY_LCTRL, 
	 'a', 's', 'd', 'f', 'g', 'h',
	'j', 'k', 'l', ';', '\'', '`', KEYMAP_KEY_LSHIFT, '\\', 'z', 'x', 'c', 'v', 'b',
	'n', 'm', ',', '.', '/', KEYMAP_KEY_RSHIFT, '*', KEYMAP_KEY_ALT,
	' ', KEYMAP_KEY_CAPS_LOCK, KEYMAP_KEY_F1, KEYMAP_KEY_F2, KEYMAP_KEY_F3, KEYMAP_KEY_F4, 
	KEYMAP_KEY_F5, KEYMAP_KEY_F6, KEYMAP_KEY_F7, KEYMAP_KEY_F8, KEYMAP_KEY_F9, 
	KEYMAP_KEY_F10, KEYMAP_KEY_KEYPAD_NUMLCK,
	KEYMAP_KEY_KEYPAD_SCRLK, '7', '8', '9', '-',
	'4', '5', '6', '+',
	'1', '2', '3', '0',
	'.', 0, 0, 0, KEYMAP_KEY_F11, KEYMAP_KEY_F12
};
unsigned int default_shift_keymap[200] =
{ 
	KEYMAP_KEY_ESC, '!', '@', '#', '$', '%',
	 '^', '&', '*', '(', ')', '_', '+', '\b', '\t',
	'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
	 'O', 'P', '{', '}', '\n', KEYMAP_KEY_LCTRL, 
	 'A', 'S', 'D', 'F', 'G', 'H',
	'J', 'K', 'L', ':', '\"', '~', KEYMAP_KEY_LSHIFT, '|', 'Z', 'X', 'C', 'V', 'B',
	'N', 'M', '<', '>', '?', KEYMAP_KEY_RSHIFT, '*', KEYMAP_KEY_ALT,
	' ', KEYMAP_KEY_CAPS_LOCK, KEYMAP_KEY_F1, KEYMAP_KEY_F2, KEYMAP_KEY_F3, KEYMAP_KEY_F4, 
	KEYMAP_KEY_F5, KEYMAP_KEY_F6, KEYMAP_KEY_F7, KEYMAP_KEY_F8, KEYMAP_KEY_F9, 
	KEYMAP_KEY_F10, KEYMAP_KEY_KEYPAD_NUMLCK,
	KEYMAP_KEY_KEYPAD_SCRLK, '7', '8', '9', '-',
	'4', '5', '6', '+',
	'1', '2', '3', '0',
	'.', 0, 0, 0, KEYMAP_KEY_F11, KEYMAP_KEY_F12
};

struct keymap keymap = 
{
	.keymap = default_keymap,
	.shift_keymap = default_shift_keymap
};
static struct input_state
{
	_Bool lshift_pressed;
	_Bool caps_enabled;
	_Bool lctrl_pressed;
	_Bool fn_pressed;
	_Bool winkey_pressed;
	_Bool lalt_pressed;
	_Bool altgr_pressed;
	_Bool menukey_pressed;
	_Bool rctrl_pressed;
	_Bool rshift_pressed;
	_Bool shift_pressed;
	unsigned int key_pressed;
} input_state = {0};

void input_callback(void *payload, size_t payload_size);
void send_event_to_kernel(uint8_t keycode)
{
	/* TODO: Use an IRQ worker when it's fixed */
	input_callback(&keycode, 1);
}
unsigned int input_process_special_key(unsigned int key, _Bool is_release)
{
	/* Simple way to shorten the code instead of a huge if statement */
	_Bool keystate = is_release ? false : true;
	input_state.key_pressed = is_release ? 0 : key;
	switch(key)
	{
		case KEYMAP_KEY_LSHIFT:
			input_state.lshift_pressed = keystate;
			input_state.shift_pressed = keystate;
			break;
		case KEYMAP_KEY_RSHIFT:
			input_state.lshift_pressed = keystate;
			input_state.shift_pressed = keystate;
			break;
		case KEYMAP_KEY_LCTRL:
			input_state.lctrl_pressed = keystate;
			break;
		case KEYMAP_KEY_FN:
			input_state.fn_pressed = keystate;
			break;
		case KEYMAP_KEY_WINKEY:
			input_state.winkey_pressed = keystate;
			break;
		case KEYMAP_KEY_ALT:
			input_state.lalt_pressed = keystate;
			break;
		case KEYMAP_KEY_ALTGR:
			input_state.altgr_pressed = keystate;
			break;
		case KEYMAP_KEY_MENU:
			input_state.menukey_pressed = keystate;
			break;
		case KEYMAP_KEY_RCTRL:
			input_state.rctrl_pressed = keystate;
			break;
		case KEYMAP_KEY_CAPS_LOCK:
			input_state.caps_enabled = keystate;
			break;
		default:
			if(is_release)
				return (unsigned int) -1; 
			return key;
	}
	return (unsigned int) -1;
}
/* Process the keypress and return -1 if it's a non-printable key */
unsigned int input_process_keypress(uint8_t keycode)
{
	_Bool is_release = false;
	if(keycode & 0x80)
		is_release = true;
	keycode &= 0x7F;

	unsigned int key = 0;

	/* TODO: Add alt support */
	if(input_state.shift_pressed || input_state.caps_enabled) key = keymap.shift_keymap[keycode-1];
	else key = keymap.keymap[keycode-1];

	return input_process_special_key(key, is_release);
}
void input_callback(void *payload, size_t payload_size)
{
	uint8_t keycode = *(uint8_t*) payload;
	unsigned int key = input_process_keypress(keycode);
	if(key != (unsigned int) -1)
		tty_recieved_character((char) key);
}
__init void init_input_state(void)
{
	memset(&input_state, 0, sizeof(struct input_state));
}
