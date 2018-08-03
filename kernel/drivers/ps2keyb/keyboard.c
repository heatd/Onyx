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

int ps2_probe(struct device *device)
{
	if(install_irq(KEYBOARD_IRQ, irq_keyb_handler, device,
			IRQ_FLAG_REGULAR, NULL) < 0)
		return -1;

	return 0;
}

struct driver ps2_driver = 
{
	.name = "ps2keyb",
	.probe = ps2_probe
};

struct device ps2dev = {.name = "ps2"};

int init_keyboard(void)
{
	ps2dev.driver = &ps2_driver;

	ps2_probe(&ps2dev);
	return 0;
}

DRIVER_INIT(init_keyboard);
