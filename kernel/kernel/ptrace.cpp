/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <uapi/user.h>

#include <onyx/process.h>
#include <onyx/ptrace.h>

#ifdef __x86_64__
long sys_ptrace(long request, pid_t pid, void *addr, void *data, void *addr2)
{
    struct process *process = get_current_process();
    switch (request)
    {
    case PTRACE_ATTACH: {
        struct process *tracee = get_process_from_pid(pid);
        if (!tracee)
        {
            return -ESRCH;
        }

        if (process_attach(process, tracee) < 0)
        {
            process_put(tracee);
            return -errno;
        }

        kernel_raise_signal(SIGSTOP, tracee, 0, NULL);

        process_put(tracee);
        return 0;
    }
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA: {
        struct process *tracee = process_find_tracee(get_current_process(), pid);
        if (!tracee)
            return -ESRCH;
        ptrace_word_t word;
        if (ptrace_peek(tracee, addr, &word) < 0)
            return -errno;
        return word;
    }
    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA: {
        struct process *tracee = process_find_tracee(get_current_process(), pid);
        if (!tracee)
            return -ESRCH;
        if (ptrace_poke(tracee, addr, (ptrace_word_t) data) < 0)
            return -errno;
        return 0;
    }
    case PTRACE_GETREGS: {
        struct process *tracee = process_find_tracee(get_current_process(), pid);
        if (!tracee)
            return -ESRCH;

        if (ptrace_getregs(tracee, (user_regs_struct *) data) < 0)
            return -errno;
        return 0;
    }
    case PTRACE_GETFPREGS: {
        struct process *tracee = process_find_tracee(get_current_process(), pid);
        if (!tracee)
            return -ESRCH;

        if (ptrace_getfpregs(tracee, (user_fpregs_struct *) data) < 0)
            return -errno;
        return 0;
    }
    case PTRACE_CONT: {
        struct process *tracee = process_find_tracee(get_current_process(), pid);
        if (!tracee)
        {
            return -ESRCH;
        }
        kernel_raise_signal(SIGCONT, tracee, 0, NULL);
        return 0;
    }
    default:
        return -EINVAL;
    }
}

#endif
