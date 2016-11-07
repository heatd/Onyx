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
#include <signal.h>
#include <stdio.h>

#include <kernel/vmm.h>
#include <kernel/signal.h>
#include <kernel/panic.h>
#include <kernel/process.h>
void kernel_default_signal(struct signal_info *sig)
{
	switch(sig->signum)
	{
		case SIGABRT:
		{
			printf("sig: Aborting!\n");
			break;
		}
	}
}
void handle_signal()
{
	process_t *curr_proc = current_process;
	if(!curr_proc)
		panic("Signal invoked without a process!");
	struct signal_info *sig = &curr_proc->sinfo;
	printf("Signal number: (%u)\n", sig->signum);
	if(sig->handler)
	{
		if(!vmm_is_mapped(sig->handler))
			return;
		printf("TODO: Handle this!\n");
	}
	else
	{
		kernel_default_signal(sig);
	}
	curr_proc->signal_pending = 0;
}