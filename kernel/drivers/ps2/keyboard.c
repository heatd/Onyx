/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <onyx/portio.h>
#include "../include/ps2.h"

void send_event_to_kernel(uint8_t keycode);

void ps2_on_byte(uint8_t byte)
{
	send_event_to_kernel(byte);
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
}