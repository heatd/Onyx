/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#define DEFAULT_UNWIND_NUMBER 6

#include <stdint.h>
#include <stdio.h>

#include <onyx/vm.h>

unsigned long get_ulong_user(void *ptr, bool *error)
{
    unsigned long l = 0;
    if (copy_from_user(&l, ptr, sizeof(unsigned long)) < 0)
    {
        *error = true;
        return 0xffffffffffffffff;
    }

    *error = false;
    return l;
}

void stack_trace_user(uintptr_t *stack)
{
    unsigned long *fp = stack;
    bool error = false;

    printk("User stack trace:\n");
    int i = 0;
    while (get_ulong_user(fp, &error) != 0 && error == false)
    {
        uintptr_t rip = get_ulong_user((fp - 1), &error);

        if (error == true)
            return;
        if (rip == 0)
            return;

        printk("<%d> %016lx\n", i++, rip);

        fp = (uintptr_t *) get_ulong_user(fp - 2, &error);

        if (error == true)
            return;
    }
    printk("Stack trace ended.\n");
}

size_t stack_trace_get(unsigned long *stack, unsigned long *pcs, size_t nr_pcs)
{
    thread_t *thread = get_current_thread();
    size_t unwinds_possible = 0;
    if (!thread) // We're still in single tasking mode, just use a safe default
        unwinds_possible = DEFAULT_UNWIND_NUMBER; // Early kernel functions don't nest a lot
    else
        unwinds_possible = 1024; /* It's safe to say the stack won't grow larger than this */

    unwinds_possible = min(unwinds_possible, nr_pcs);
    uint64_t *fp = stack;
    size_t i;
    for (i = 0; i < unwinds_possible; i++)
    {
        if (thread)
        {
            if ((uintptr_t) fp & 0x7)
                break;

            unsigned long stack_base = ((unsigned long) thread->kernel_stack_top) - 0x4000;

            if (fp >= thread->kernel_stack_top)
                break;
            if (fp - 2 < (unsigned long *) stack_base)
                break;
        }

        if (!(void *) *(fp - 1))
            break;

        auto ip = (unsigned long) *(fp - 1);
        if (ip < VM_HIGHER_HALF)
            break;

        pcs[i] = ip;

        fp = (uint64_t *) *(fp - 2);
        if (!fp)
            break;
    }

    if (i != unwinds_possible)
        pcs[i] = 0;

    return i;
}

char *resolve_sym(void *address);
void stack_trace_ex(unsigned long *stack)
{
    unsigned long pcs[32];
    const size_t nr = stack_trace_get(stack, pcs, sizeof(pcs) / sizeof(unsigned long));
    for (size_t i = 0; i < nr; i++)
    {
        printk("Stack frame #%lu: %lx\n", i, pcs[i]);
    }
}

void stack_trace()
{
    stack_trace_ex((unsigned long *) __builtin_frame_address(1));
}
