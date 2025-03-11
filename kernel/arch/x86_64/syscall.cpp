/*
 * Copyright (c) 2018 - 2025 Pedro Falcato
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

extern "C" void handle_signal(struct registers *regs);

__always_inline bool should_sysret(struct registers *regs)
{
    /* We can't use sysret on a number of occasions. Most of these would be triggered by ptrace or
     * sigreturn messing about. */

    /* If rcx != rip or regs->r11, the normal sysret path will not restore registers correctly
     * (we'll corrupt rcx and/or r11) */
    if (regs->rcx != regs->rip || regs->r11 != regs->rflags)
        return false;

    if (regs->cs != USER_CS || regs->ss != USER_DS)
        return false;

    /* Intel CPUs stumble with sysret to non-canonical addresses. They'll give us a kernel-side #GP
     * with a user stack, which is not what we want */
    if (regs->rip >= VM_USER_ADDR_LIMIT)
        return false;
    /* Note: Linux rejects sysret if EFLAGS.TF or RF here */
    return true;
}

extern "C" long do_syscall64(struct syscall_frame *frame)
{
    context_tracking_enter_kernel();
    CHECK(frame == task_curr_syscall_frame());
    /* In case of a fork or sigreturn, adjust %rdi so it points to the frame */
    if (frame->rax == SYS_fork || frame->rax == SYS_sigreturn || frame->rax == SYS_vfork)
        frame->rdi = (unsigned long) frame;

    /* sigaltstack's implementation requires the syscall frame as the 3rd argument */
    if (frame->rax == SYS_sigaltstack)
        frame->rdx = (unsigned long) frame;

    unsigned long syscall_nr = frame->rax;
    long ret = 0;

    proc_event_enter_syscall(frame, frame->rax);

    if (likely(syscall_nr <= NR_SYSCALL_MAX))
    {
        ret = syscall_table_64[syscall_nr](frame->rdi, frame->rsi, frame->rdx, frame->r10,
                                           frame->r8, frame->r9);
    }
    else
        ret = -ENOSYS;

#if 0
    if (ret < 0)
        printk("Error doing syscall %ld = %ld (%s)\n", syscall_nr, ret, strerror(-ret));
#endif
    proc_event_exit_syscall(ret, syscall_nr);

    context_tracking_exit_kernel();

    if (WARN_ON(sched_is_preemption_disabled()))
    {
        pr_err("Trying to return from a syscall (%ld) with preemption disabled! Fixing up...\n",
               syscall_nr);
        write_per_cpu(preemption_counter, 0);
    }

    frame->rax = ret;
    if (signal_is_pending())
        handle_signal((struct registers *) frame);
    return likely(should_sysret((struct registers *) frame));
}
