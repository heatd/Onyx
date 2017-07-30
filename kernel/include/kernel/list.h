/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_LIST_H
#define _KERNEL_LIST_H

#include <stdlib.h>

#include <kernel/compiler.h>

struct list_head
{
	void *ptr __align_cache;
	struct list_head *next __align_cache;
};
static inline int list_add(struct list_head *list, void *ptr)
{
	struct list_head *new_item = (struct list_head*) malloc(sizeof(struct list_head));
	if(!new_item)
		return -1;
	new_item->ptr = ptr;
	new_item->next = NULL;

	while(list->next) list = list->next;
	
	list->next = new_item;
	return 0;
}
static inline void *list_get_element(struct list_head *list, void **saveptr)
{
	if(!*saveptr)
	{
		*saveptr = list;
		return list->ptr;
	}
	else
	{
		struct list_head *current = (struct list_head*) *saveptr;
		struct list_head *next = current->next;
		*saveptr = next;
		if(!next)
			return NULL;
		return next->ptr;
	}
}
#endif
