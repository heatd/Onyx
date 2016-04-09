/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
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
#include <kernel/kheap.h>
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

static _Bool is_shift_pressed = false;
void SendEventToKern(uint8_t keycode)
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
	if (is_shift_pressed == true && c > 96 && c < 123) {
		printf("%c", c - 32);
		return;
	}
	printf("%c", c);
}
