/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <onyx/err.h>
#include <onyx/internal_abi.h>
#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>
#include <onyx/vm.h>

namespace native
{

void arch_save_thread(thread *thread, void *stack)
{
    assert(thread->canary == THREAD_STRUCT_CANARY);
    /* No need to save the fpu context if we're a kernel thread! */
    if (!(thread->flags & THREAD_KERNEL))
    {
        save_fpu(thread->fpu_area);
        thread->tpidr = mrs("tpidr_el0");
    }
}

void arch_load_thread(thread *thread, unsigned int cpu)
{
    auto data = abi::get_abi_data();

    data->kernel_stack = (unsigned long) thread->kernel_stack_top;

    if (!(thread->flags & THREAD_KERNEL))
    {
        restore_fpu(thread->fpu_area);
        msr("tpidr_el0", (unsigned long) thread->tpidr);
    }
    else
    {
        // If we're a kernel thread, load the address space if its not &kernel_address_space
        // since it may be a special one like efi_aspace
        // This is not done for user threads since those get loaded later on
        if (thread->aspace != &kernel_address_space)
            panic("TODO");
    }
}

void arch_load_process(process *process, thread *thread, unsigned int cpu)
{
    vm_load_aspace(thread->get_aspace(), cpu);
    __native_tlb_invalidate_all();
}

extern "C" [[noreturn]] void arm64_context_switch(thread *prev, unsigned char *stack,
                                                  bool needs_to_kill_prev);
[[noreturn]] void arch_context_switch(thread *prev, thread *next)
{
    // arm64_context_switch wants interrupts to be disabled
    irq_disable();

    struct registers *regs = (struct registers *) next->kernel_stack;

    assert(regs->pc != 0);

    bool is_last_dead = prev && prev->status == THREAD_DEAD;
    arm64_context_switch(prev, (unsigned char *) next->kernel_stack, is_last_dead);
}

int arch_transform_into_user_thread(thread *thread)
{
    thread->fpu_area = (unsigned char *) fpu_allocate_state();

    if (!thread->fpu_area)
        return -ENOMEM;
    memset(thread->fpu_area, 0, fpu_get_save_size());

    setup_fpu_area(thread->fpu_area);
    /* Note that we don't adjust the addr limit because the thread might be us */
    return 0;
}

} // namespace native
