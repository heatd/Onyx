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

irq_list_t *irq_routines[16]  =
{
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};
void irq_install_handler(int irq, irq_t handler)
{
	irq_list_t *lst = irq_routines[irq];
	if(!lst)
	{
		lst = (irq_list_t*)malloc(sizeof(irq_list_t));
		memset(lst, 0, sizeof(irq_list_t));
		lst->handler = handler;
		irq_routines[irq] = lst;
		return;
	}
	while(lst->next != NULL)
		lst = lst->next;
	lst->next = (irq_list_t*)malloc(sizeof(irq_list_t));
	lst->next->handler = handler;
	lst->next->next = NULL;
}
void irq_uninstall_handler(int irq, irq_t handler)
{
	irq_list_t *list = irq_routines[irq];
	if(list->handler == handler)
	{
		irq_list_t *list = irq_routines[irq];
		free(list);
		list = list->next;
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
void irq_handler(uint64_t irqn)
{
	irq_list_t *handlers = irq_routines[irqn - 32];
	for(irq_list_t *i = handlers; i != NULL;i = i->next)
	{
		irq_t handler = i->handler;
		handler();
	}
	pic_send_eoi(irqn - 32);
}