/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef PS2_H
#define PS2_H

#include <stdint.h>
#include <stdbool.h>

#include <onyx/mutex.h>
#include <onyx/input/device.h>

#define PS2_CMD_OK		0x00
#define PS2_CMD_TIMEOUT		0xff

#define PS2_COMMAND		0x64
#define PS2_DATA		0x60

#define PS2_CTRLR_CONFIG_FIRST_PORT_IRQ 	(1 << 0)
#define PS2_CTRLR_CONFIG_SECOND_PORT_IRQ 	(1 << 1)
#define PS2_CTRLR_CONFIG_SECOND_PORT_CLOCK	(1 << 5)
#define PS2_CTRLR_CONFIG_FIRST_PORT_TRANSLATION (1 << 6)

#define PS2_STATUS_OUTPUT_BUFFER_FULL	(1 << 0)
#define PS2_STATUS_INPUT_BUFFER_FULL	(1 << 1)

#define PS2_CMD_DISABLE_SECOND_PORT	0xa7
#define PS2_CMD_ENABLE_SECOND_PORT 	0xa8
#define PS2_CMD_DEVICE_RESET		0xff
#define PS2_CMD_TEST_FIRST_PORT		0xab
#define PS2_CMD_TEST_SECOND_PORT	0xa9
#define PS2_CMD_SEND_BYTE_TO_PORT2	0xd2
#define PS2_CMD_WRITE_PORT2_INPUT	0xd4
#define PS2_CMD_TEST_CONTROLLER		0xaa
#define PS2_CMD_ENABLE_FIRST_PORT	0xae
#define PS2_CMD_DISABLE_FIRST_PORT	0xad
#define PS2_CMD_READ_INTERNAL_RAM	0x20
#define PS2_CMD_WRITE_INTERNAL_RAM	0x60

#define PS2_PORT1_IRQ 	1
#define PS2_PORT2_IRQ	12

#define PS2_INIT_OK	0x55

struct ps2_controller;
struct input_dev;

struct ps2_port
{
	unsigned int irq;
	bool has_device;
	int port_number;
	struct ps2_controller *controller;
	void (*on_byte)(struct ps2_port *port);
	struct input_device dev;
};

struct ps2_controller
{
	struct device *device;
	struct mutex controller_lock;
	uint16_t data_port;
	uint16_t command_port;
	unsigned int nr_ports;
	struct ps2_port ports[2];
	unsigned int irqs[2];
};

void ps2_keyboard_init(struct ps2_port *port);
uint8_t ps2_send_command_to_device(struct ps2_port *port, uint8_t command,
	bool get_response, uint8_t *response);
void ps2_wait_for_input_buffer(struct ps2_controller *controller);
uint8_t ps2_read_data(struct ps2_port *port);

#endif
