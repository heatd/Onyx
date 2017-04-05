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
/**************************************************************************
 *
 *
 * File: irq.c
 *
 * Description: Contains irq installation functions
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <kernel/registers.h>
#include <kernel/irq.h>

volatile _Bool is_in_irq = false;
irq_list_t *irq_routines[24]  =
{
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};
_Bool isirq()
{
	return is_in_irq;
}
void irq_install_handler(int irq, irq_t handler)
{
	irq_list_t *lst = irq_routines[irq];
	if(!lst)
	{
		lst = (irq_list_t*) malloc(sizeof(irq_list_t));
		if(!lst)
		{
			errno = ENOMEM;
			return; /* TODO: Return a value indicating an error */
		}
		memset(lst, 0, sizeof(irq_list_t));
		lst->handler = handler;
		irq_routines[irq] = lst;
		return;
	}
	while(lst->next != NULL)
		lst = lst->next;
	lst->next = (irq_list_t*) malloc(sizeof(irq_list_t));
	if(!lst->next)
	{
		errno = ENOMEM;
		return; /* See the above TODO */
	}
	lst->next->handler = handler;
	lst->next->next = NULL;
}
void irq_uninstall_handler(int irq, irq_t handler)
{
	irq_list_t *list = irq_routines[irq];
	if(list->handler == handler)
	{
		free(list);
		irq_routines[irq] = NULL;
		return;
	}
	irq_list_t *prev = NULL;
	while(list->handler != handler)
	{
		prev = list;
		list = list->next;
	}
	free(list);
	prev->next = list->next;
}
uintptr_t irq_handler(uint64_t irqn, registers_t *regs)
{
	if(irqn > 23)
	{
		return (uintptr_t) regs;
	}
	uintptr_t ret = (uintptr_t) regs;
	irq_list_t *handlers = irq_routines[irqn];
	if(!handlers)
		printf("Unhandled interrupt at IRQ %u\n", irqn);
	is_in_irq = true;
	for(irq_list_t *i = handlers; i != NULL;i = i->next)
	{
		irq_t handler = i->handler;
		uintptr_t p = handler(regs);
		if(p != 0)
		{
			ret = p;
		}
	}
	is_in_irq = false;
	return ret;
}
