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
        uintptr_t rip = get_ulong_user((fp + 1), &error);

        if (error == true)
            return;
        if (rip == 0)
            return;

        printk("<%d> %016lx\n", i++, rip);

        fp = (uintptr_t *) get_ulong_user(fp, &error);

        if (error == true)
            return;
    }
    printk("Stack trace ended.\n");
}

char *resolve_sym(void *address);
__attribute__((no_sanitize_undefined)) void stack_trace_ex(unsigned long *stack)
{
    size_t return_addresses = 0;
    // Get all the unwinds possible using threading structures
    thread_t *thread = get_current_thread();
    size_t unwinds_possible = 0;
    if (!thread) // We're still in single tasking mode, just use a safe default
        unwinds_possible = DEFAULT_UNWIND_NUMBER; // Early kernel functions don't nest a lot
    else
        unwinds_possible = 1024; /* It's safe to say the stack won't grow larger than this */

    unsigned long *fp = stack;
    for (size_t i = 0; i < unwinds_possible; i++)
    {
        /*if(thread)
        {
            if((unsigned long*) *fp >= thread->kernel_stack_top)
                break;
        }*/

        printk("fp: %p\n", fp);

        void *retaddr = (void *) *(fp + 1);
        if (!retaddr)
            break;
#if 0
        char *s = resolve_sym((void *) *(fp + 1));
        if (!s)
            break;
#endif
        printk("Stack trace #%lu: %p\n", i, retaddr);

#if 0
        free(s);
#endif
        fp = (unsigned long *) *fp;
        if (!fp)
            break;

        return_addresses++;
    }
}

void stack_trace(void)
{
    return;
    stack_trace_ex((unsigned long *) __builtin_frame_address(1));
}
