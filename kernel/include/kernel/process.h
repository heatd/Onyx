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
#ifndef _PROCESS_H
#define _PROCESS_H
#include <kernel/task_switching.h>
#include <kernel/vmm.h>
#include <kernel/ioctx.h>
#define THREADS_PER_PROCESS 30
typedef struct proc
{
	thread_t *threads[30];
	uint64_t brk;
	uint64_t data_area;
	int errno;
	vmm_entry_t *areas;
	size_t num_areas;
	const char *cmd_line;
	ioctx_t ctx;
	struct proc *parent;
	struct proc *next;
} process_t;

#endif
