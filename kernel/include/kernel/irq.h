/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _IRQ_H
#define _IRQ_H
#include <stdbool.h>

#include <kernel/registers.h>
#ifdef __x86_64__
#include <kernel/apic.h>
#endif
typedef uintptr_t(*irq_t)(registers_t *);

typedef struct irq
{
	irq_t handler;
	struct irq *next;
}irq_list_t;

extern volatile _Bool is_in_irq;
_Bool isirq();
void irq_install_handler(int irq, irq_t handler);
void irq_uninstall_handler(int irq, irq_t handler);

#endif
