/*
 * Copyright (c) 2022 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/internal_abi.h>
#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/vm.h>

#include <onyx/atomic.hpp>

atomic<int> curr_id = 1;
constexpr unsigned long kernel_stack_size = 0x4000;
constexpr bool adding_guard_page = true;

namespace arm64::internal
{

void thread_setup_stack(thread *thread, bool is_user, const registers_t *regs)
{
    registers_t *kregs = ((registers_t *) thread->kernel_stack) - 1;
    memcpy(kregs, regs, sizeof(*kregs));

    kregs->pstate = 0;

    if (is_user)
    {
        // TODO
    }
    else
    {
        kregs->pstate = 0b0101;
        kregs->sp = reinterpret_cast<uint64_t>(thread->kernel_stack);
    }

    thread->kernel_stack = (uint64_t *) kregs;
}

void kernel_thread_start(void *arg)
{
    auto thread = get_current_thread();

    thread->entry(arg);

    thread_exit();
}

} // namespace arm64::internal

extern "C" void thread_finish_destruction(void *___thread)
{
    thread *thread = static_cast<thread_t *>(___thread);

#if 1
    /* Destroy the kernel stack */
    unsigned long stack_base = ((unsigned long) thread->kernel_stack_top) - kernel_stack_size;
    if (adding_guard_page)
        stack_base -= PAGE_SIZE;
    auto pages = adding_guard_page ? 6 : 4;

    vfree((void *) stack_base, pages);
#endif
    /* Free the fpu area */
    free(thread->fpu_area);

    thread_remove_from_list(thread);

    memset_explicit(&thread->lock, 0x80, sizeof(struct spinlock));
    ((volatile struct thread *) thread)->canary = THREAD_DEAD_CANARY;
    /* Free the thread */
    delete thread;
}

thread *sched_spawn_thread(registers_t *regs, unsigned int flags, void *tp)
{
    thread *new_thread = new thread;

    if (!new_thread)
        return NULL;

    new_thread->id = curr_id++;
    new_thread->flags = flags;
    new_thread->canary = THREAD_STRUCT_CANARY;
    new_thread->fpu_area = nullptr;

    bool is_user = !(flags & THREAD_KERNEL);
    auto pages = adding_guard_page ? 6 : 4;
    void *original_entry = (void *) regs->pc;

    if (is_user)
    {
        new_thread->fpu_area = (unsigned char *) fpu_allocate_state();

        if (!new_thread->fpu_area)
            goto error;

        memset(new_thread->fpu_area, 0, fpu_get_save_size());

        setup_fpu_area(new_thread->fpu_area);

        new_thread->addr_limit = VM_USER_ADDR_LIMIT;

        new_thread->owner = get_current_process();
        new_thread->set_aspace(get_current_process()->get_aspace());
    }
    else
    {
        new_thread->addr_limit = VM_KERNEL_ADDR_LIMIT;

        // Set trampoline as the starting RIP
        regs->pc = (unsigned long) arm64::internal::kernel_thread_start;
        new_thread->set_aspace(&kernel_address_space);
    }

    cputime_info_init(new_thread);

    new_thread->refcount = 1;

    new_thread->kernel_stack =
        static_cast<uintptr_t *>(vmalloc(pages, VM_TYPE_STACK, VM_READ | VM_WRITE));

    // printk("Allocating %p - %p\n\n", new_thread->kernel_stack,
    //       (char *) new_thread->kernel_stack + (pages << PAGE_SHIFT));

    if (!new_thread->kernel_stack)
    {
        goto error;
    }

    if (adding_guard_page)
    {
        unsigned char *p = (unsigned char *) new_thread->kernel_stack;
        // TODO: vmalloc memory doesn't support mprotecting
        // vm_mprotect(&kernel_address_space, new_thread->kernel_stack, PAGE_SIZE, 0);
        // vm_mprotect(&kernel_address_space, p + PAGE_SIZE + kernel_stack_size, PAGE_SIZE, 0);
        new_thread->kernel_stack = (uintptr_t *) (p + PAGE_SIZE);
    }

    new_thread->kernel_stack =
        reinterpret_cast<uintptr_t *>(((char *) new_thread->kernel_stack + kernel_stack_size));
    new_thread->kernel_stack_top = new_thread->kernel_stack;

    arm64::internal::thread_setup_stack(new_thread, is_user, regs);

    new_thread->tpidr = tp;

    thread_append_to_global_list(new_thread);

    new_thread->priority = SCHED_PRIO_NORMAL;

    if (!is_user)
    {
        // thread_setup_stack makes the entry = %rip, but in this case, it's not true since we're
        // using a trampoline. Therefore, we need to save the original rip up there so
        // we can restore it.
        new_thread->entry = reinterpret_cast<thread_callback_t>(original_entry);
    }

    return new_thread;

error:
    if (new_thread->fpu_area)
        free(new_thread->fpu_area);

    delete new_thread;

    return NULL;
}

thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void *args)
{
    /* Create the thread context (aka the real work) */
    registers_t regs = {};
    regs.pc = (unsigned long) callback;
    regs.x[0] = (unsigned long) args;
    regs.pstate = 0;

    thread_t *t = sched_spawn_thread(&regs, flags, NULL);
    return t;
}

int process_alloc_stack(struct stack_info *info)
{
    void *ptr =
        vm_mmap(nullptr, info->length, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, nullptr, 0);
    if (!ptr)
        return -ENOMEM;
    info->base = ptr;
    info->top = reinterpret_cast<void *>((unsigned long) ptr + info->length);

    return 0;
}

namespace native
{

void arch_save_thread(thread *thread, void *stack)
{
    assert(thread->canary == THREAD_STRUCT_CANARY);
    /* No need to save the fpu context if we're a kernel thread! */
    if (!(thread->flags & THREAD_KERNEL))
    {
        save_fpu(thread->fpu_area);
        thread->tpidr = (void *) mrs("tpidr_el0");
    }
}

void arch_load_thread(thread *thread, unsigned int cpu)
{
    auto data = abi::get_abi_data();
    data->kernel_stack = (unsigned long) thread->kernel_stack_top;
    // auto regs = (registers_t *) thread->kernel_stack;

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
        // auto kspace = thread->get_aspace();
        // if (kspace != &kernel_address_space)
        //     vm_load_aspace(kspace, cpu);
    }

    // Note: We know that abi data is guaranteed to be the first member of tp, so we can use it as
    // an address
#if 0
    if (in_kernel_space_regs(regs))
        riscv_write_csr(RISCV_SSCRATCH, 0);
    else
        riscv_write_csr(RISCV_SSCRATCH, data);
#endif
}

void arch_load_process(process *process, thread *thread, unsigned int cpu)
{
    vm_load_aspace(thread->get_aspace(), cpu);
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

extern "C" void arm64_thread_put(thread *t)
{
    thread_put(t);
}
