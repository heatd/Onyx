/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>

#include <onyx/list.h>

void list_assert_correct(struct list_head *head)
{
#if 0
	if(list_is_empty(head))
		return;

	for(struct list_head *h = head->next, *next = head->next->next; h != head; h = h->next, next = h->next)
	{
		assert(h != LIST_REMOVE_POISON);
		assert(next != LIST_REMOVE_POISON);
		assert(next->prev == h);
	}
#else
	return;
#endif
}
