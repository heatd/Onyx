/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <kernel/irq.h>
#include <kernel/pic.h>
#include <kernel/portio.h>
#include <kernel/panic.h>

#include <drivers/ps2.h>

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
int init_keyboard()
{
	irq_t handler = &irq_keyb_handler;
	irq_install_handler(KEYBOARD_IRQ, handler);
	return 0;
}
