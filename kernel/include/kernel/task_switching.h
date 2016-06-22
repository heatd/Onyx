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

#ifndef _TASK_SWITCHING_AMD64_H
#define _TASK_SWITCHING_AMD64_H
#include <stdint.h>
typedef void(*ThreadCallback)(void*);
typedef struct thr
{
	uintptr_t *user_stack;
	uintptr_t *kernel_stack;
	uintptr_t *kernel_stack_top;
	uintptr_t *user_stack_top;
	ThreadCallback rip;
	uint32_t flags;
	struct thr *next;
} thread_t;
thread_t *sched_create_thread(ThreadCallback callback, uint32_t flags, void* args);
thread_t *get_current_thread();
 #endif
