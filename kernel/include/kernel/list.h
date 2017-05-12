/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_LIST_H
#define _KERNEL_LIST_H

#include <kernel/compiler.h>

struct list_head
{
	void *ptr __align_cache;
	struct list_head *next __align_cache;
};

#endif