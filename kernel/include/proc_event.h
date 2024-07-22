/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _PROC_EVENT_H_
#define _PROC_EVENT_H_

#include <onyx/types.h>
#include <sys/user.h>
#define PROC_EVENT_LISTEN_SYSCALLS (1 << 0)

#define PROCEVENT_ACK 0

#define PROC_EVENT_SYSCALL_ENTER 0
#define PROC_EVENT_SYSCALL_EXIT  1

struct syscall_exit
{
    long retval;
    long syscall_nr;
};

struct proc_event
{
    int type;
    pid_t pid;
    pid_t thread;

    union {
        struct user_regs_struct syscall;
        struct syscall_exit syscall_exit;
    } e_un;
};

int proc_event_attach(pid_t pid, unsigned long flags);

#endif
