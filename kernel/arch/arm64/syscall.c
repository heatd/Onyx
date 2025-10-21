/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/gen/syscall.h>
#include <onyx/proc_event.h>

#include <platform/syscall.h>

typedef long (*syscall_callback_t)(unsigned long r0, unsigned long r1, unsigned long r2,
                                   unsigned long r3, unsigned long r4, unsigned long r5);

extern syscall_callback_t syscall_table_64[];

long do_syscall64(registers_t *frame)
{
    unsigned long syscall_nr = frame->x[8];
    long ret = 0;

    proc_event_enter_syscall((struct syscall_frame *) frame, syscall_nr);

    if (likely(syscall_nr <= NR_SYSCALL_MAX))
    {
        ret = syscall_table_64[syscall_nr](frame->x[0], frame->x[1], frame->x[2], frame->x[3],
                                           frame->x[4], frame->x[5]);
    }
    else
        ret = -ENOSYS;

    proc_event_exit_syscall(ret, syscall_nr);
    context_tracking_exit_kernel();

    return ret;
}
