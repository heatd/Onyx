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

#include <drivers/ps2.h>

#define PS2_PNP "PNP0303"
static struct device *ps2_device = NULL;

struct driver ps2_driver = 
{
	.name = "ps2keyb"
};

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

int init_keyboard(void)
{
	if((ps2_device = (struct device *) acpi_get_device(PS2_PNP)) != NULL)
	{
		INFO("ps2", "Found PS/2 device in the ACPI bus\n");
	}
	else	return 0;

	ps2_device->name = strdup("ps2");
	if(!ps2_device->name)
		return -1;
	driver_register_device(&ps2_driver, ps2_device);

	irq_t handler = &irq_keyb_handler;
	if(install_irq(KEYBOARD_IRQ, handler, ps2_device, IRQ_FLAG_REGULAR, NULL) < 0)
		return -1;

	return 0;
}
