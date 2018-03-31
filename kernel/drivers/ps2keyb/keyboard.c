/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <onyx/irq.h>
#include <onyx/pic.h>
#include <onyx/portio.h>
#include <onyx/panic.h>
#include <onyx/acpi.h>
#include <onyx/log.h>
#include <onyx/driver.h>

#include <drivers/ps2.h>

#define PS2_PNP "PNP0303"

extern void send_event_to_kernel(unsigned char keycode);
irqstatus_t irq_keyb_handler(struct irq_context *ctx, void *cookie)
{
	unsigned char status;
	unsigned char keycode;
	status = inb(PS2_STATUS);
	if(status & 0x01)
	{
		keycode = inb(PS2_DATA);
		send_event_to_kernel(keycode);
	}

	return IRQ_HANDLED;
}

struct acpi_dev_id ps2_devids[] =
{
	{PS2_PNP},
	{NULL}
};

void ps2_probe(struct device *device)
{
	if(install_irq(KEYBOARD_IRQ, irq_keyb_handler, device,
			IRQ_FLAG_REGULAR, NULL) < 0)
		return;
}

struct driver ps2_driver = 
{
	.name = "ps2keyb",
	.devids = &ps2_devids,
	.probe = ps2_probe
};

int init_keyboard(void)
{
	acpi_bus_register_driver(&ps2_driver);
	return 0;
}

DRIVER_INIT(init_keyboard);
