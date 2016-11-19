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
#ifndef _KERNEL_DATA_STRUCTURES_H
#define _KERNEL_DATA_STRUCTURES_H

#include <stdlib.h>

typedef struct queue
{
	void *data;
	struct queue *prev, *next;
} queue_t;

inline int queue_add_to_tail(queue_t *queue, void *data)
{
	queue_t *new = malloc(sizeof(queue_t));
	if(!new)
		return 1;
	
	memset(new, 0, sizeof(queue_t));

	queue_t *it = queue;
	while(it->next)
		it = it->next;
	
	it->next = new;
	new->prev = it;
	new->data = data;
	return 0;
}
inline int queue_add_to_head(queue_t *queue, void *data)
{
	queue_t *new = malloc(sizeof(queue_t));
	if(!new)
		return 1;
	
	memset(new, 0, sizeof(queue_t));

	queue_t *it = queue;
	while(it->prev)
		it = it->prev;
	
	it->prev = new;
	new->prev = NULL;
	new->data = data;
	new->next = it;
	return 0;
}







#endif