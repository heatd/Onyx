/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <stdio.h>

#include <onyx/cpu.h>
#include <onyx/err.h>
#include <onyx/process.h>
#include <onyx/user.h>
#include <onyx/vm.h>
#include <onyx/x86/msr.h>
#include <onyx/x86/shadow_stack.h>

void *alloc_shadow_stack(unsigned long size);

static int shstk_assign_stack(struct thread *thr)
{
    unsigned long stack_size;
    void *shstk;

    if (!thr->shadow_stack_base)
    {
        stack_size = rlim_get_cur(RLIMIT_STACK);
        shstk = alloc_shadow_stack(stack_size);
        if (IS_ERR(shstk))
            return PTR_ERR(shstk);
        thr->shadow_stack_base = shstk;
        thr->shadow_stack_size = stack_size;
    }

    return 0;
}

void shstk_clear(void)
{
    if (current->thr->shstk_state)
    {
        wrmsr(IA32_U_CET, 0);
        wrmsr(IA32_PL3_SSP, 0);
    }

    current->thr->shstk_state = 0;
    current->thr->shadow_stack_base = current->thr->shadow_stack = NULL;
    current->thr->shadow_stack_size = 0;
}

static int shstk_enable(struct thread *curthr)
{
    unsigned long stack;
    int err;

    if (!x86_has_cap(X86_FEATURE_CET_SS))
        return -EOPNOTSUPP;

    err = shstk_assign_stack(curthr);
    if (err)
        return err;
    stack = (unsigned long) curthr->shadow_stack_base + curthr->shadow_stack_size;

    /* There are discreet races between preemption save/restore logic, and us configuring CET. As
     * such, while we're touching any of this state, don't allow for preemption.
     */
    sched_disable_preempt();
    curthr->shstk_state |= ARCH_SHSTK_SHSTK;
    wrmsr(IA32_U_CET, curthr->shstk_state);
    wrmsr(IA32_PL3_SSP, stack);
    curthr->shadow_stack = (void *) stack;
    sched_enable_preempt();
    return 0;
}

int shstk_clone_thread(struct thread *newthr, struct thread *src)
{
    int err;

    err = shstk_assign_stack(newthr);
    if (err)
        return err;
    newthr->shstk_state = src->shstk_state;
    newthr->shadow_stack = newthr->shadow_stack_base + newthr->shadow_stack_size;
    return 0;
}

int shstk_prctl(int code, unsigned long arg)
{
    struct thread *curthr = get_current_thread();

    if (code == ARCH_SHSTK_STATUS)
        return copy_to_user((unsigned long *) arg, &curthr->shstk_state, sizeof(unsigned long));
    if (code == ARCH_SHSTK_ENABLE)
    {
        if (arg & ARCH_SHSTK_SHSTK)
            return shstk_enable(curthr);
    }
    else
    {
        /* TODO */
        return -EINVAL;
    }
    return 0;
}
