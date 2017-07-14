/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_DATA_STRUCTURES_H
#define _KERNEL_DATA_STRUCTURES_H

#include <stdlib.h>
#include <string.h>

typedef struct queue
{
	void *data;
	struct queue *prev, *next;
} queue_t;

static inline int queue_add_to_tail(queue_t *queue, void *data, queue_t *new_queue)
{
	queue_t *new;
	if(!new_queue)
	{
		new = malloc(sizeof(queue_t));
		if(!new)
			return 1;
		memset(new, 0, sizeof(queue_t));

	}
	else
		new = new_queue;
	queue_t *it = queue;
	while(it->next != NULL)
		it = it->next;
	
	it->next = new;
	new->prev = it;
	new->data = data;
	return 0;
}
static inline int queue_add_to_head(queue_t *queue, void *data)
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
