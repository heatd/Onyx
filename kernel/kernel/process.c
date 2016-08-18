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
#include <stdint.h>
#include <stdlib.h>
#include <kernel/process.h>
process_t *first_process = NULL;
process_t *current_process = NULL;
uint64_t current_pid = 1;
process_t *process_create(const char *cmd_line, ioctx_t *ctx, process_t *parent)
{
	process_t *proc = malloc(sizeof(process_t));
	proc->pid = current_pid;
	current_pid++;
	proc->cmd_line = cmd_line;
	// TODO: Setup proc->ctx
	if(ctx)
		memcpy(&proc->ctx, ctx, sizeof(ioctx_t));
	if(parent)
		proc->parent = parent;

	if(!first_process)
		first_process = proc;
	else
	{
		process_t *it = first_process;
		while(it->next) it = it->next;
		it->next = proc;
	}
	return proc;
}
void process_create_thread(process_t *proc, ThreadCallback callback, uint32_t flags, void* args)
{
	thread_t *thread = sched_create_thread(callback, flags, args);
	int is_set = 0;
	for(int i = 0; i < THREADS_PER_PROCESS; i++)
	{
		if(proc->threads[i] == NULL)
		{
			proc->threads[i] = thread;
			thread->owner = proc;
			is_set = 1;
		}
	}
	if(!is_set)
		sched_destroy_thread(thread);
}
