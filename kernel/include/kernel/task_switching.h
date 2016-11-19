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
typedef void(*thread_callback_t)(void*);
struct proc;
typedef struct thr
{
	uintptr_t *user_stack;
	uintptr_t *kernel_stack;
	uintptr_t *kernel_stack_top;
	uintptr_t *user_stack_top;
	struct proc *owner;
	thread_callback_t rip;
	uint32_t flags;
	int id;
	struct thr *next;
} thread_t;
thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void* args);
thread_t* sched_create_main_thread(thread_callback_t callback, uint32_t flags,int argc, char **argv, char **envp);
void sched_destroy_thread(thread_t *thread);
thread_t *get_current_thread();
uintptr_t *sched_fork_stack(uintptr_t *stack, uintptr_t *forkregstack, uintptr_t *rsp, uintptr_t rip);
void* sched_switch_thread(void* last_stack);
#endif
