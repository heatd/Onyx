/*
 * Copyright (c) 2022 Pedro Falcato
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

typedef long (*syscall_callback_t)(unsigned long rdi, unsigned long rsi, unsigned long rdx,
                                   unsigned long r10, unsigned long r8, unsigned long r9);

extern syscall_callback_t syscall_table_64[];

long do_syscall64(registers_t *frame)
{
    unsigned long syscall_nr = frame->a7;
    long ret = 0;

    frame->orig_a0 = frame->a0;
    proc_event_enter_syscall((syscall_frame *) frame, frame->a7);

    if (likely(syscall_nr <= NR_SYSCALL_MAX))
    {
        ret = syscall_table_64[syscall_nr](frame->a0, frame->a1, frame->a2, frame->a3, frame->a4,
                                           frame->a5);
    }
    else
        ret = -ENOSYS;

#if 0
    // if (ret < 0)
    printk("Doing syscall %ld = %ld\n", syscall_nr, ret);
#endif
    proc_event_exit_syscall(ret, syscall_nr);

    context_tracking_exit_kernel();

    return ret;
}
