/*
* Copyright (c) 2016, 2017, 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <onyx/irq.h>
#include <onyx/port_io.h>
#include <onyx/panic.h>
#include <onyx/acpi.h>
#include <onyx/log.h>
#include <onyx/driver.h>
#include <onyx/cpu.h>
#include <onyx/timer.h>

#include <onyx/x86/platform_info.h>

#include "../include/ps2.h"

extern void send_event_to_kernel(unsigned char keycode);

irqstatus_t ps2_irq(struct irq_context *ctx, void *cookie)
{
	unsigned char status;

	struct ps2_port *port = (ps2_port *) cookie;

	status = inb(port->controller->command_port);

	if(status & PS2_STATUS_OUTPUT_BUFFER_FULL)
	{
		if(port->on_byte)
			port->on_byte(port);
	}

	return IRQ_HANDLED;
}

uint8_t ps2_send_command(struct ps2_controller *controller, uint8_t command,
	bool get_response, uint8_t *response)
{
	mutex_lock(&controller->controller_lock);

	while(inb(controller->command_port) & PS2_STATUS_INPUT_BUFFER_FULL)
		cpu_relax();

	outb(controller->command_port, command);

	uint64_t t = get_tick_count();
	uint64_t future = t + 100;

	if(get_response)
	{
		/* Wait until the output buffer is full to read the response
		 * from the data port
		*/
		while(!(inb(controller->command_port)
			& PS2_STATUS_OUTPUT_BUFFER_FULL))
		{
			if(future <= get_tick_count())
			{
				mutex_unlock(&controller->controller_lock);
				return PS2_CMD_TIMEOUT;
			}

			cpu_relax();
		}

		*response = inb(controller->data_port);
	}

	mutex_unlock(&controller->controller_lock);

	return PS2_CMD_OK;
}

uint8_t ps2_send_command_to_device(struct ps2_port *port, uint8_t command,
	bool get_response, uint8_t *response)
{
	if(port->port_number == 2)
	{
		ps2_send_command(port->controller, PS2_CMD_WRITE_PORT2_INPUT,
			false, NULL);
	}

	while(inb(port->controller->command_port)
		& PS2_STATUS_INPUT_BUFFER_FULL)
		cpu_relax();

	uint64_t t = get_tick_count();
	uint64_t future = t + 100;
	outb(port->controller->data_port, command);

	if(get_response)
	{
		/* Wait until the output buffer is full to read the response
		 * from the data port
		*/
		while(!(inb(port->controller->command_port)
			& PS2_STATUS_OUTPUT_BUFFER_FULL))
		{
			if(future <= get_tick_count())
			{
				return PS2_CMD_TIMEOUT;
			}

			cpu_relax();
		}

		*response = inb(port->controller->data_port);
	}

	return PS2_CMD_OK;
}

uint8_t ps2_read_internal_ram(struct ps2_controller *controller, uint8_t index)
{
	uint8_t internal_ram = 0;

	/* TODO: Test for timeouts? But maybe it's not a as huge of an issue
	 * as it sounds...
	*/
	ps2_send_command(controller, PS2_CMD_READ_INTERNAL_RAM + index,
		true, &internal_ram);
	return internal_ram;
}

void ps2_wait_for_input_buffer(struct ps2_controller *controller)
{
	while(inb(controller->command_port) & PS2_STATUS_INPUT_BUFFER_FULL)
		cpu_relax();
}

void ps2_write_internal_ram(struct ps2_controller *controller, uint8_t index,
	uint8_t val)
{
	ps2_send_command(controller, PS2_CMD_WRITE_INTERNAL_RAM + index,
		false, NULL);

	ps2_wait_for_input_buffer(controller);

	outb(controller->data_port, val);
}

uint8_t ps2_read_controller_config(struct ps2_controller *controller)
{
	return ps2_read_internal_ram(controller, 0);
}

void ps2_write_controller_config(struct ps2_controller *controller,
	uint8_t val)
{
	ps2_write_internal_ram(controller, 0, val);
}

void ps2_disable_ports(struct ps2_controller *controller)
{
	ps2_send_command(controller, PS2_CMD_DISABLE_FIRST_PORT, false, NULL);

	ps2_send_command(controller, PS2_CMD_DISABLE_SECOND_PORT, false, NULL);
}

void ps2_flush_output(struct ps2_controller *controller)
{
	while(inb(controller->command_port) & PS2_STATUS_OUTPUT_BUFFER_FULL)
	{
		inb(controller->data_port);
	}
}

bool ps2_do_self_test(struct ps2_controller *controller)
{
	uint8_t response;
	if(ps2_send_command(controller,
		PS2_CMD_TEST_CONTROLLER, true, &response) == PS2_CMD_TIMEOUT)
	{
		printf("ps2: Controller timeout during self-test\n");
		return false;
	}

	if(response != PS2_INIT_OK)
	{
		printf("ps2: Controller test failed, response %02x\n",
			response);
		return false;
	}

	return true;
}

void ps2_disable_irqs(struct ps2_controller *controller)
{
	uint8_t config = ps2_read_controller_config(controller);

	config &= ~(PS2_CTRLR_CONFIG_FIRST_PORT_IRQ |
		   PS2_CTRLR_CONFIG_SECOND_PORT_IRQ |
		   PS2_CTRLR_CONFIG_FIRST_PORT_TRANSLATION);

	ps2_write_controller_config(controller, config);
}

void ps2_test_for_port2(struct ps2_controller *controller)
{
	ps2_send_command(controller, PS2_CMD_ENABLE_SECOND_PORT, false, NULL);

	uint8_t config = ps2_read_controller_config(controller);

	if(!(config & PS2_CTRLR_CONFIG_SECOND_PORT_CLOCK))
		controller->nr_ports = 2;
	else
		controller->nr_ports = 1;
	
	ps2_send_command(controller, PS2_CMD_DISABLE_SECOND_PORT, false, NULL);
}

int ps2_enable_irqs(struct ps2_controller *controller)
{
	uint8_t byte = ps2_read_controller_config(controller);

	byte |= PS2_CTRLR_CONFIG_FIRST_PORT_IRQ  |
		PS2_CTRLR_CONFIG_SECOND_PORT_IRQ |
		PS2_CTRLR_CONFIG_FIRST_PORT_TRANSLATION;

	ps2_write_controller_config(controller, byte);

	for(unsigned int i = 0; i < controller->nr_ports; i++)
		if(install_irq(controller->ports[i].irq, ps2_irq,
			controller->device, 0, &controller->ports[i])
			< 0)
				return -1;

	return 0;
}

int ps2_reset_device(struct ps2_port *port)
{
	uint8_t response = 0;

	if(ps2_send_command_to_device(port, PS2_CMD_DEVICE_RESET, true,
		&response) == PS2_CMD_TIMEOUT)
	{
		printf("PS2 reset timed out\n");
		port->has_device = false;
		return -1;
	}

	if(response == 0xfc || response == 0xfd)
	{
		printf("PS2 reset bad response\n");
		return -1;
	}


	ps2_wait_for_input_buffer(port->controller);

	while((response = inb(port->controller->data_port)) == 0xfa)
		ps2_wait_for_input_buffer(port->controller);

	if(response != 0xaa)
	{
		port->has_device = false;
		printf("PS2 reset bad response %x\n", response);
		return -1;
	}

	if(port->port_number == 2)
	{
		/* The mouse outputs another byte */
		ps2_wait_for_input_buffer(port->controller);
		inb(port->controller->data_port);
	}

	port->has_device = true;

	return 0;
}

int ps2_enable_port(struct ps2_port *port)
{
	if(port->port_number == 1)
		ps2_send_command(port->controller,
			PS2_CMD_ENABLE_FIRST_PORT, false, NULL);
	else
		ps2_send_command(port->controller, PS2_CMD_ENABLE_SECOND_PORT,
			false, NULL);
	return ps2_reset_device(port);
}

bool ps2_init_port(struct ps2_port *port)
{
	uint8_t response = 0;
	if(port->port_number == 1)
	{
		if(ps2_send_command(port->controller,
			PS2_CMD_TEST_FIRST_PORT, true, &response) == PS2_CMD_TIMEOUT)
		{
			printf("ps2: Port 1 test timeout\n");
			return false;
		}
	}
	else
	{
		if(ps2_send_command(port->controller,
			PS2_CMD_TEST_SECOND_PORT, true, &response) == PS2_CMD_TIMEOUT)
		{
			printf("ps2: Port 2 test timeout\n");
			return false;
		}
	}

	if(response != 0)
	{
		printf("ps2: PS/2 test failed on port %u,"
		       "with response %u\n", port->port_number, response);
		return false;
	}

	if(ps2_enable_port(port) < 0)
	{
		printf("ps2: Failed to enable port %u\n", port->port_number);

		return false;
	}

	return true;
}

void ps2_init_ports(struct ps2_controller *controller)
{
	for(unsigned int i = 0; i < controller->nr_ports; i++)
	{
		struct ps2_port *port = &controller->ports[i];

		port->port_number = i + 1;
		port->controller = controller;
		port->irq = controller->irqs[i];

		ps2_init_port(port);

		if(port->has_device)
			printf("ps2: Port %u has device\n", port->port_number);
	}
}

uint16_t i8042_data_port = 0;
uint16_t i8042_command_port = 0;
uint32_t i8042_keyboard_irq = 0;
uint32_t i8042_mouse_irq = 0;
bool i8042_found_pnp = false;

int ps2_probe(struct device *device)
{
	/* TODO: Support other types of PS/2 controllers that are not
	 * necessarily ISA PS/2 controllers with the default I/O port
	 * and IRQ setup */

	struct ps2_controller *controller = (ps2_controller *) zalloc(sizeof(*controller));
	
	if(!controller)
		return -1;

	printf("ps2 controller cmd %02x; data %02x; kirq %u; mirq %u\n",
		i8042_command_port, i8042_data_port, i8042_keyboard_irq, i8042_mouse_irq);
	controller->command_port = i8042_command_port;
	controller->data_port = i8042_data_port;
	controller->device = device;
	controller->irqs[0] = i8042_keyboard_irq;
	controller->irqs[1] = i8042_mouse_irq;
	mutex_init(&controller->controller_lock);

	/* Flush the output */
	ps2_flush_output(controller);

	/* Disable ports */
	ps2_disable_irqs(controller);

	/* Do controller self test */
	if(!ps2_do_self_test(controller))
	{
		free(controller);
		return -1;
	}

	ps2_disable_ports(controller);

	/* Test if a second port exists */
	ps2_test_for_port2(controller);

	/* Initialize ports */
	ps2_init_ports(controller);

	if(controller->ports[0].has_device)
		ps2_keyboard_init(&controller->ports[0]);
	
	if(ps2_enable_irqs(controller) < 0)
		printf("ps2: Could not enable irqs\n");
	/* TODO: Add a mouse driver */
	return 0;
}

uint8_t ps2_read_data(struct ps2_port *port)
{
	return inb(port->controller->data_port);
}

static struct acpi_dev_id acpi_keyboard_ids[] =
{
	{"PNP0300"},
	{"PNP0301"},
	{"PNP0302"},
	{"PNP0303"},
	{"PNP0304"},
	{"PNP0305"},
	{"PNP0306"},
	{"PNP0309"},
	{"PNP030a"},
	{"PNP030b"},
	{"PNP0320"},
	{"PNP0343"},
	{"PNP0344"},
	{"PNP0345"},
	{"CPQA0D7"},
	{NULL},
};

static struct acpi_dev_id acpi_mouse_ids[] =
{
	{"AUI0200"},
	{"FCJ6000"},
	{"FCJ6001"},
	{"PNP0f03"},
	{"PNP0f0b"},
	{"PNP0f0e"},
	{"PNP0f12"},
	{"PNP0f13"},
	{"PNP0f19"},
	{"PNP0f1c"},
	{"SYN0801"},
	{NULL},
};


int ps2_probe_keyboard(struct device *device);
int ps2_probe_mouse(struct device *device);

struct driver ps2_keyboard_driver = 
{
	.name = "ps2keyb",
	.devids = &acpi_keyboard_ids,
	.probe = ps2_probe_keyboard
};

struct driver ps2_mouse_driver = 
{
	.name = "ps2mouse",
	.devids = &acpi_mouse_ids,
	.probe = ps2_probe_mouse,
};

struct driver ps2_platform_driver = 
{
	.name = "ps2"
};

struct device ps2_platform_device = {.name = "ps2"};

int ps2_probe_keyboard(struct device *device)
{
	struct acpi_device *dev = (struct acpi_device *) device;

	ACPI_RESOURCE *data_port, *command_port, *irq_res, *eirq_res;

	data_port = acpi_get_resource(dev, ACPI_RESOURCE_TYPE_IO, 0);
	command_port = acpi_get_resource(dev, ACPI_RESOURCE_TYPE_IO, 1);
	irq_res = acpi_get_resource(dev, ACPI_RESOURCE_TYPE_IRQ, 0);
	eirq_res = acpi_get_resource(dev, ACPI_RESOURCE_TYPE_EXTENDED_IRQ, 0);

	if(data_port)
		i8042_data_port = data_port->Data.Io.Minimum;
	if(command_port)
		i8042_command_port = command_port->Data.Io.Minimum;
	if(irq_res)
		i8042_keyboard_irq = irq_res->Data.Irq.Interrupts[0];
	else if(eirq_res)
		i8042_keyboard_irq = eirq_res->Data.ExtendedIrq.Interrupts[0];

	i8042_found_pnp = true;
	return 0;
}

int ps2_probe_mouse(struct device *device)
{
	struct acpi_device *dev = (struct acpi_device *) device;

	ACPI_RESOURCE *data_port, *command_port, *irq_res, *eirq_res;

	data_port = acpi_get_resource(dev, ACPI_RESOURCE_TYPE_IO, 0);
	command_port = acpi_get_resource(dev, ACPI_RESOURCE_TYPE_IO, 1);
	irq_res = acpi_get_resource(dev, ACPI_RESOURCE_TYPE_IRQ, 0);
	eirq_res = acpi_get_resource(dev, ACPI_RESOURCE_TYPE_EXTENDED_IRQ, 0);

	if(data_port)
		i8042_data_port = data_port->Data.Io.Minimum;
	if(command_port)
		i8042_command_port = command_port->Data.Io.Minimum;
	if(irq_res)
		i8042_mouse_irq = irq_res->Data.Irq.Interrupts[0];
	else if(eirq_res)
		i8042_mouse_irq = eirq_res->Data.ExtendedIrq.Interrupts[0];

	i8042_found_pnp = true;
	return 0;
}

int ps2_try_pnp(void)
{
	if(i8042_found_pnp)
	{
		if(!i8042_command_port)
			return -1;
		if(!i8042_data_port)
			return -1;

		return 0;
	}

	return -1;
}

int ps2_init(void)
{
	if(x86_platform.i8042 == I8042_PLATFORM_ABSENT)
			return -1;

	ps2_platform_device.driver = &ps2_platform_driver;

	acpi_bus_register_driver(&ps2_keyboard_driver);
	acpi_bus_register_driver(&ps2_mouse_driver);

	if(ps2_try_pnp() < 0)
	{
		if(x86_platform.i8042 == I8042_FIRMWARE_ABSENT)
			return -1;
		
		printf("ps2: Could not find PNP device - falling back to "
			"ISA values\n");
		i8042_command_port = PS2_COMMAND;
		i8042_data_port = PS2_DATA;
		i8042_keyboard_irq = PS2_PORT1_IRQ;
		i8042_mouse_irq = PS2_PORT2_IRQ;
	}

	if(!i8042_command_port)
		i8042_command_port = PS2_COMMAND;

	if(!i8042_data_port)
		i8042_data_port = PS2_DATA;
	
	if(!i8042_keyboard_irq) i8042_keyboard_irq = PS2_PORT1_IRQ;
	if(!i8042_mouse_irq) i8042_mouse_irq = PS2_PORT2_IRQ;

	return ps2_probe(&ps2_platform_device);
}

MODULE_INIT(ps2_init);
MODULE_INSERT_VERSION();
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_AUTHOR("Pedro Falcato");

