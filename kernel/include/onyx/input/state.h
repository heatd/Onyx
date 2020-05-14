/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_INPUT_STATE_H
#define _ONYX_INPUT_STATE_H

#include <stdbool.h>

#include <onyx/input/keys.h>

struct input_state
{
	/* TODO: I don't think we need a lock here */
	bool shift_pressed;
	bool caps_enabled;
	bool alt_pressed;
	bool ctrl_pressed;
	unsigned long keys_pressed[2];
};

#ifdef __cplusplus
extern "C" {
#endif

void input_state_set_key_state(keycode_t key, bool pressed, struct input_state *is);
bool input_state_key_is_pressed(keycode_t key, struct input_state *is);
bool input_state_toggle_key(keycode_t key, struct input_state *is);

#ifdef __cplusplus
}
#endif

#endif
