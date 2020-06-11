/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <onyx/x86/syscall.h>
#include <onyx/proc_event.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>

typedef long (*syscall_callback_t)(unsigned long rdi, unsigned long rsi,
				   unsigned long rdx, unsigned long r10,
				   unsigned long r8, unsigned long r9);

extern syscall_callback_t syscall_table_64[];

long do_syscall64(struct syscall_frame *frame)
{
	/* In case of a fork or sigreturn, adjust %rdi so it points to the frame */
	if(frame->rax == SYS_fork || frame->rax == SYS_rt_sigreturn)
		frame->rdi = (unsigned long) frame;

	/* sigaltstack's implementation requires the syscall frame as the 3rd argument */
	if(frame->rax == SYS_sigaltstack)
		frame->rdx = (unsigned long) frame;

	long syscall_nr = frame->rax;
	long ret = 0;

	proc_event_enter_syscall(frame, frame->rax);

	if(likely(syscall_nr <= NR_SYSCALL_MAX))
	{
		ret = syscall_table_64[syscall_nr](frame->rdi, frame->rsi,
						   frame->rdx, frame->r10,
						   frame->r8, frame->r9);
	}
	else
		ret = -ENOSYS;
	//printk("Doing syscall %lu = %lu\n", frame->rax, ret);

	proc_event_exit_syscall(ret, syscall_nr);

	return ret;
}
