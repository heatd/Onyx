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
#include <stdio.h>
#include <drivers/ps2.h>
extern void SendEventToKern(unsigned char keycode);
/* This took a while to make... Some keys still remain, but I don't need them right now */
void keyb_handler()
{
	unsigned char status;
	unsigned char keycode;
	status = inb(PS2_STATUS);

	if(status & 0x01){
		keycode = inb(PS2_DATA);
		SendEventToKern(keycode);
	}
}
int InitKeyboard()
{
	irq_t handler = &keyb_handler;
	PIC::UnmaskIRQ(1);
	IRQ::InstallHandler(1,handler);
	return 0;
}
