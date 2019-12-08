/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_SIGNAL_H
#define _ONYX_X86_SIGNAL_H

#define _GNU_SOURCE
#include <ucontext.h>
#include <signal.h>

struct sigframe
{
	void *retaddr;
	ucontext_t uc;
	siginfo_t sinfo;
	char fpregs[0];
};

#endif