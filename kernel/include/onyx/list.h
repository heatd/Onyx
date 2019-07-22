/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_LIST_H
#define _KERNEL_LIST_H

#include <stdlib.h>

#include <onyx/compiler.h>

/* 
 * TODO: This code is weird, inconsistent, and needs to be rewritten
 * and re-thought.
*/
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

static inline void list_remove(struct list_head *list, void *ptr)
{
	if(list->ptr == ptr)
	{
		list->ptr = NULL;
		return;
	}

	for(struct list_head *l = list; l->next; l = l->next)
	{
		if(l->next->ptr == ptr)
		{
			struct list_head *a = l->next;
			l->next = a->next;
			free(a);
			return;
		}
	}
}

struct list_node
{
	void *ptr;
	struct list_node *prev, *next;
};

struct list
{
	struct list_node *head, *tail;
};

static inline int list_add_node(struct list *l, void *ptr)
{
	struct list_node *node = (struct list_node *) malloc(sizeof(struct list_node));
	if(!node)
		return -1;
	
	node->ptr = ptr;
	node->prev = NULL;
	node->next = NULL;

	if(l->head)
	{
		l->tail->next = node;
		node->prev = l->tail;
		l->tail = node;
	}
	else
	{
		l->head = l->tail = node;
	}

	return 0;
}

static inline int __list_remove_node(struct list *l, struct list_node *n, void *ptr)
{
	while(n != NULL)
	{
		if(n->ptr == ptr)
		{
			if(n->prev)
				n->prev->next = n->next;
			else
				l->head = n->next;

			if(n->next)
				n->next->prev = n->prev;
			else
				l->tail = n->prev;
	
			free(n);

			return 0;
		}

		n = n->next;
	}

	return -1;
}

static inline int list_remove_node(struct list *l, void *ptr)
{
	return __list_remove_node(l, l->head, ptr);
}

static inline void list_destroy(struct list *l)
{
	struct list_node *n = l->head;

	while(n != NULL)
	{
		struct list_node *old_n = n;
		n = n->next;
		free(old_n);
	}

	l->head = l->tail = NULL;
}
#endif
