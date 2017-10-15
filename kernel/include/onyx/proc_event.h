/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>

#include <onyx/scheduler.h>
#include <onyx/process.h>

#include <proc_event.h>

struct proc_event_sub
{
	thread_t *waiting_thread;
	unsigned long flags;
	bool valid_sub;
	unsigned long has_new_event;
	struct process *target_process;
	struct proc_event event_buf;
	struct proc_event_sub *next;
};
