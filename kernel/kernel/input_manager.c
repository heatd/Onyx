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

#include <kernel/log.h>
#include <kernel/tty.h>
#include <kernel/irq.h>
#include <kernel/keys.h>
unsigned int keys[200] =
{ 
	0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
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
struct input_state
{
	_Bool lshift_pressed;
	_Bool caps_pressed;
	_Bool lctrl_pressed;
	_Bool fn_pressed;
	_Bool winkey_pressed;
	_Bool lalt_pressed;
	_Bool altgr_pressed;
	_Bool menukey_pressed;
	_Bool rctrl_pressed;
	_Bool rshift_pressed;
	_Bool shift_pressed;
	int key_pressed;
} input_state;

void input_callback(void *payload, size_t payload_size);
void send_event_to_kernel(uint8_t keycode)
{
	if(keycode == 0x2A || keycode == 0x36)
	{
		input_state.shift_pressed = true;
		return;
	}
	if(keycode == 0xAA || keycode == 0xB6)
	{
		input_state.shift_pressed = false;
		return;
	}
	if(keycode & 0x80)
		return;
	if(irq_schedule_work(input_callback, sizeof(uint8_t), &keycode))
	{
		ERROR("ps2keyb", "Couldn't schedule IRQ work!\n");
	}
}
void input_callback(void *payload, size_t payload_size)
{
	uint8_t keycode = *(uint8_t*) payload;
	printk("Keycode: %x\n", keycode);
	tty_recieved_character(0);
}