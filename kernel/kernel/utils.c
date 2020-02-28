/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <stdlib.h>

#include <onyx/utils.h>
#include <onyx/vm.h>
#include <onyx/scheduler.h>

void *memdup(void *ptr, size_t size)
{
	void *new_ptr = malloc(size);
	if(!new_ptr)
		return NULL;
	memcpy(new_ptr, ptr, size);
	return new_ptr;
}

void *copy_page_to_page(void *p1, void *p2)
{
	return copy_page(PHYS_TO_VIRT(p1), p2);
}

void *copy_page(void *vaddr, void *p2)
{
	return memcpy(vaddr, PHYS_TO_VIRT(p2), PAGE_SIZE);
}
