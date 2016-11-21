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
#include <errno.h>
#include <kernel/process.h>
process_t *first_process = NULL;
process_t *current_process = NULL;
uint64_t current_pid = 1;
process_t *process_create(const char *cmd_line, ioctx_t *ctx, process_t *parent)
{
	process_t *proc = malloc(sizeof(process_t));
	if(!proc)
		return errno = ENOMEM, NULL;
	memset(proc, 0, sizeof(process_t));
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
		process_t *it = current_process;
		while(it->next) it = it->next;
		it->next = proc;
	}
	return proc;
}
static int c;
void process_create_thread(process_t *proc, thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp)
{
	c++;
	thread_t *thread = NULL;
	if(!argv)
		thread = sched_create_thread(callback, flags, NULL);
	else
		thread = sched_create_main_thread(callback, flags, argc, argv, envp);
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
	/*if(!is_set)
		sched_destroy_thread(thread);*/
}
extern int curr_id;
void process_fork_thread(process_t *dest, process_t *src, int thread_index)
{
	dest->threads[thread_index] = malloc(sizeof(thread_t));
	memcpy(dest->threads[thread_index], src->threads[thread_index], sizeof(thread_t));
	thread_add(dest->threads[thread_index]);
	dest->threads[thread_index]->id = curr_id++;
	dest->threads[thread_index]->owner = dest;
}
process_t *get_process_from_pid(pid_t pid)
{
	process_t *p = first_process;
	for(;p;p = p->next)
	{
		if(p->pid == pid)
			return p;
	}
	return NULL;
}
