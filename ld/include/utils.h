/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _H_UTILS_H
#define _H_UTILS_H

#include <stdlib.h>
void *read_file(const char *path);

typedef struct linked_list
{
	void *data;
	struct linked_list *next;
} linked_list_t;
inline int list_insert(linked_list_t *list, void *obj)
{
	for(; list->next; list = list->next);
	list->next = malloc(sizeof(linked_list_t));
	if(!list->next)
		return -1;
	list->next->data = obj;
	list->next->next = NULL;

	return 0;
}

#endif