/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_SIGNAL_H
#define _ONYX_X86_SIGNAL_H

#include <ucontext.h>
#include <signal.h>


/* This struct needs to be exactly like user-space's ucontext_t, but without
 * __fpregs_mem which is a huge 512-byte member designed for makecontext, etc.
 * We don't need that and it's huge.
 */
struct __sigcontext
{
	unsigned long uc_flags;
	stack_t uc_stack;
	mcontext_t uc_mcontext;
	sigset_t uc_sigmask;
};

struct sigframe
{
	void *retaddr;
	struct __sigcontext uc;
	siginfo_t sinfo;
	char fpregs[0];
};

#endif
