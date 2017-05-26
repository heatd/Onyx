/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#include <kernel/process.h>
#include <kernel/ptrace.h>

#include <sys/ptrace.h>
#include <sys/user.h>

long sys_ptrace(long request, pid_t pid, void *addr, void *data, void *addr2)
{
	process_t *process = get_current_process();
	switch(request)
	{
		case PTRACE_ATTACH:
		{
			process_t *tracee = get_process_from_pid(pid);
			if(!tracee)
			{
				return -ESRCH;
			}
			if(process_attach(process, tracee) < 0)
				return -errno;
			/* TODO: Send SIGSTOP to the tracee */
			return 0;
		}
		case PTRACE_PEEKTEXT:
		case PTRACE_PEEKDATA:
		{
			process_t *tracee = process_find_tracee(get_current_process(), pid);
			if(!tracee)
				return -ESRCH;
			ptrace_word_t word;
			if(ptrace_peek(tracee, addr, &word) < 0)
				return -errno;
			return word;
		}
		case PTRACE_POKETEXT:
		case PTRACE_POKEDATA:
		{
			process_t *tracee = process_find_tracee(get_current_process(), pid);
			if(!tracee)
				return -ESRCH;
			if(ptrace_poke(tracee, addr, (ptrace_word_t) data) < 0)
				return -errno;
			return 0;
		}
		case PTRACE_GETREGS:
		{
			process_t *tracee = process_find_tracee(get_current_process(), pid);
			if(!tracee)
				return -ESRCH;
			if(vmm_check_pointer(data, sizeof(struct user_regs_struct)) < 0)
				return -EFAULT;
			if(ptrace_getregs(tracee, data) < 0)
				return -errno;
			return 0;
		}
		case PTRACE_GETFPREGS:
		{
			process_t *tracee = process_find_tracee(get_current_process(), pid);
			if(!tracee)
				return -ESRCH;
			if(vmm_check_pointer(data, sizeof(struct user_fpregs_struct)) < 0)
				return -EFAULT;
			if(ptrace_getfpregs(tracee, data) < 0)
				return -errno;
			return 0;
		}
		default:
			return -EIO;
	}
}
