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
/**************************************************************************
 *
 *
 * File: irq.c
 *
 * Description: Contains irq instalation functions
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/

#include <kernel/pic.h>
#include <kernel/irq.h>
#include <stdlib.h>
#include <stdio.h>
irq_t irq_routines[16]  =
{
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};
void irq_install_handler(int irq, irq_t handler)
{
	irq_routines[irq] = handler;
}
void irq_uninstall_handler(int irq)
{
	irq_routines[irq] = NULL;
}
void irq_handler(uint64_t irqn)
{
	irq_t handler = irq_routines[irqn - 32];
	if(handler)
		handler();
	pic_send_eoi(irqn - 32);
}
