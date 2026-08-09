/*
 * Copyright (c) 2017 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PTRACE_H
#define _ONYX_PTRACE_H

#include <stdint.h>

#include <onyx/compiler.h>

#include <uapi/signal.h>
#include <uapi/user.h>

__BEGIN_CDECLS

typedef long ptrace_word_t;

long arch_ptrace(long request, struct process *task, unsigned long addr, unsigned long data,
                 unsigned long addr2);
int __ptrace_stop(int code, unsigned long message, siginfo_t *info);
void ptrace_syscall(void);
__END_CDECLS
#endif
