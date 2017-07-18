/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <kernel/irq.h>
#include <kernel/pic.h>
#include <kernel/portio.h>
#include <kernel/panic.h>
#include <kernel/acpi.h>
#include <kernel/log.h>

#include <drivers/ps2.h>

#define PS2_PNP "PNP0303"
extern void send_event_to_kernel(unsigned char keycode);
static uintptr_t irq_keyb_handler(registers_t *regs)
{
	unsigned char status;
	unsigned char keycode;
	status = inb(PS2_STATUS);
	if(status & 0x01)
	{
		keycode = inb(PS2_DATA);
		send_event_to_kernel(keycode);
	}
	return 0;
}
int init_keyboard(void)
{
	if(acpi_get_device(PS2_PNP))
	{
		INFO("ps2", "Found PS/2 device in the ACPI bus\n");
	}
	else	return 0;
	irq_t handler = &irq_keyb_handler;
	irq_install_handler(KEYBOARD_IRQ, handler);
	return 0;
}
