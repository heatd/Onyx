/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
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

#include <kernel/tty.h>
unsigned char keys[200] =
    { 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
	'\t',
	'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
	0, 'a', 's', 'd', 'f', 'g', 'h',
	'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v', 'b',
	'n', 'm', ',', '.', '/', 0, '*', 0,
	' ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '7', '8', '9', '-',
	'4', '5', '6', '+', '1', '2', '3', '0',
	'.', 0, 0, 0, 0, 0
};
char num_shft[] = {'!','\"','#','$','%','&','/','(',')','='};
static _Bool is_shift_pressed = false;
// TODO: Improve this crap
void send_event_to_kernel(uint8_t keycode)
{
	if (keycode == 0x2A || keycode == 0x36) {
		is_shift_pressed = true;
		return;
	}
	if (keycode == 0xAA || keycode == 0xB6) {
		is_shift_pressed = false;
		return;
	}
	if (keycode & 0x80)
		return;
	char c = keys[keycode - 1];
	if (is_shift_pressed == true && c > 96 && c < 123)
		c = c-32;
	else if(is_shift_pressed && c > 47 && c < 58)
		c = num_shft[c - 49];
	tty_recieved_character(c);
}
