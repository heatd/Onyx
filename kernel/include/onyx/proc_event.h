/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <proc_event.h>
#include <stdbool.h>

#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/semaphore.h>
#include <onyx/syscall.h>

struct proc_event_sub
{
    thread_t *waiting_thread;
    unsigned long flags;
    bool valid_sub;
    unsigned long has_new_event;
    struct semaphore event_semaphore;
    struct process *target_process;
    struct proc_event event_buf;
    struct proc_event_sub *next;
};

void proc_event_enter_syscall(struct syscall_frame *regs, uintptr_t rax);
void proc_event_exit_syscall(long retval, long syscall_nr);
