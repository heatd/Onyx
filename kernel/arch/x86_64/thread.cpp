/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include <onyx/cpu.h>
#include <onyx/elf.h>
#include <onyx/fpu.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/process.h>
#include <onyx/spinlock.h>
#include <onyx/syscall.h>
#include <onyx/task_switching.h>
#include <onyx/timer.h>
#include <onyx/tss.h>
#include <onyx/vm.h>
#include <onyx/worker.h>
#include <onyx/x86/apic.h>
#include <onyx/x86/eflags.h>
#include <onyx/x86/msr.h>
#include <onyx/x86/segments.h>

#include <platform/vm_layout.h>

#include <onyx/atomic.hpp>

/* Creates a thread for the scheduler to switch to
   Expects a callback for the code(RIP) and some flags
*/
atomic<int> curr_id = 1;
constexpr unsigned long kernel_stack_size = 0x4000;

namespace x86
{

namespace internal
{

void thread_setup_stack(thread *thread, bool is_user, registers_t *regs)
{
    uint64_t *stack = thread->kernel_stack;
    uint64_t ds, cs, rflags = regs->rflags;

    if (is_user)
    {
        ds = USER_DS;
        cs = USER_CS;
    }
    else
    {
        ds = KERNEL_DS;
        cs = KERNEL_CS;
        regs->rsp = reinterpret_cast<uint64_t>(thread->kernel_stack);
    }

    thread->entry = reinterpret_cast<thread_callback_t>(regs->rip);
    *--stack = ds;        // SS
    *--stack = regs->rsp; // RSP
    *--stack = rflags;    // RFLAGS
    *--stack = cs;        // CS
    *--stack = regs->rip; // RIP

    /* Skip int_no and int_err_code */
    stack -= 2;

    *--stack = regs->rax; // RAX
    *--stack = regs->rbx; // RBX
    *--stack = regs->rcx; // RCX
    *--stack = regs->rdx; // RDX
    *--stack = regs->rdi; // RDI
    *--stack = regs->rsi; // RSI
    *--stack = regs->rbp; // RBP
    *--stack = regs->r8;  // r8
    *--stack = regs->r9;  // r9
    *--stack = regs->r10; // r10
    *--stack = regs->r11; // R11
    *--stack = regs->r12; // R12
    *--stack = regs->r13; // R13
    *--stack = regs->r14; // R14
    *--stack = regs->r15; // R15
    *--stack = ds;        // DS

    thread->kernel_stack = stack;
}

void kernel_thread_start(void *arg)
{
    auto thread = get_current_thread();

    thread->entry(arg);

    thread_exit();
}

} // namespace internal

} // namespace x86

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

int sys_arch_prctl(int code, unsigned long *addr)
{
    struct thread *current = get_current_thread();
    switch (code)
    {
        case ARCH_SET_FS: {
            current->fs = (void *) addr;
            wrmsr(FS_BASE_MSR, (uintptr_t) current->fs);
            break;
        }
        case ARCH_GET_FS: {
            if (copy_to_user(addr, &current->fs, sizeof(unsigned long)) < 0)
                return -EFAULT;
            break;
        }
        case ARCH_SET_GS: {
            current->gs = (void *) addr;
            wrmsr(KERNEL_GS_BASE, (uintptr_t) current->gs);
            break;
        }
        case ARCH_GET_GS: {
            if (copy_to_user(addr, current->gs, sizeof(unsigned long)) < 0)
                return -EFAULT;
            break;
        }
    }

    return 0;
}

constexpr bool adding_guard_page = true;

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

    memset_s(&thread->lock, 0x80, sizeof(struct spinlock));
    ((volatile struct thread *) thread)->canary = THREAD_DEAD_CANARY;
    /* Free the thread */
    delete thread;
}

thread *sched_spawn_thread(registers_t *regs, unsigned int flags, void *fs)
{
    thread *new_thread = new thread;

    if (!new_thread)
        return NULL;

    new_thread->id = curr_id++;
    new_thread->flags = flags;
    new_thread->canary = THREAD_STRUCT_CANARY;

    bool is_user = !(flags & THREAD_KERNEL);
    auto pages = adding_guard_page ? 6 : 4;
    void *original_entry = (void *) regs->rip;

    if (is_user)
    {
        posix_memalign((void **) &new_thread->fpu_area, fpu_get_save_alignment(),
                       fpu_get_save_size());

        if (!new_thread->fpu_area)
            goto error;

        memset(new_thread->fpu_area, 0, fpu_get_save_size());

        setup_fpu_area(new_thread->fpu_area);

        new_thread->addr_limit = VM_USER_ADDR_LIMIT;

        new_thread->owner = get_current_process();
        new_thread->set_aspace(get_current_address_space());
    }
    else
    {
        new_thread->addr_limit = VM_KERNEL_ADDR_LIMIT;

        // Set trampoline as the starting RIP
        regs->rip = (unsigned long) x86::internal::kernel_thread_start;
        new_thread->set_aspace(&kernel_address_space);
    }

    cputime_info_init(new_thread);

    new_thread->refcount = 1;

    new_thread->kernel_stack =
        static_cast<uintptr_t *>(vmalloc(pages, VM_TYPE_STACK, VM_READ | VM_WRITE));

    if (!new_thread->kernel_stack)
    {
        goto error;
    }

    if (adding_guard_page)
    {
        unsigned char *p = (unsigned char *) new_thread->kernel_stack;

        vm_mprotect(&kernel_address_space, new_thread->kernel_stack, PAGE_SIZE, 0);
        vm_mprotect(&kernel_address_space, p + PAGE_SIZE + kernel_stack_size, PAGE_SIZE, 0);
        new_thread->kernel_stack = (uintptr_t *) (p + PAGE_SIZE);
    }

    new_thread->kernel_stack =
        reinterpret_cast<uintptr_t *>(((char *) new_thread->kernel_stack + kernel_stack_size));
    new_thread->kernel_stack_top = new_thread->kernel_stack;

    x86::internal::thread_setup_stack(new_thread, is_user, regs);

    new_thread->fs = fs;

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

PER_CPU_VAR_NOUNUSED(unsigned long kernel_stack) = 0;
PER_CPU_VAR_NOUNUSED(unsigned long scratch_rsp) = 0;

thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void *args)
{
    /* Create the thread context (aka the real work) */
    registers_t regs = {};
    regs.rip = (unsigned long) callback;
    regs.rdi = (unsigned long) args;
    regs.rflags = default_rflags;

    thread_t *t = sched_spawn_thread(&regs, flags, NULL);
    return t;
}

extern "C" [[noreturn]] void x86_context_switch(thread *prev, unsigned char *stack,
                                                bool needs_to_kill_prev);

namespace native
{

void arch_save_thread(thread *thread, void *stack)
{
    assert(thread->canary == THREAD_STRUCT_CANARY);
    /* No need to save the fpu context if we're a kernel thread! */
    if (!(thread->flags & THREAD_KERNEL))
        save_fpu(thread->fpu_area);
}

void arch_load_thread(struct thread *thread, unsigned int cpu)
{
    assert(thread->canary == THREAD_STRUCT_CANARY);

    write_per_cpu(kernel_stack, thread->kernel_stack_top);
    /* Fill the TSS with a kernel stack */
    set_kernel_stack((uintptr_t) thread->kernel_stack_top);

    if (!(thread->flags & THREAD_KERNEL))
    {
        restore_fpu(thread->fpu_area);

        wrmsr(FS_BASE_MSR, (uint64_t) thread->fs);
        wrmsr(KERNEL_GS_BASE, (uint64_t) thread->gs);
    }
    else
    {
        // If we're a kernel thread, load the address space if its not &kernel_address_space
        // since it may be a special one like efi_aspace
        // This is not done for user threads since those get loaded later on
        auto kspace = thread->get_aspace();
        if (kspace != &kernel_address_space)
            vm_load_aspace(kspace, cpu);
    }
}

void arch_load_process(struct process *process, struct thread *thread, unsigned int cpu)
{
    auto as = thread->get_aspace();
    vm_load_aspace(as, cpu);
}

void arch_context_switch(thread *prev, thread *next)
{
    bool is_last_dead = prev && prev->status == THREAD_DEAD;
    x86_context_switch(prev, (unsigned char *) next->kernel_stack, is_last_dead);
}

int arch_transform_into_user_thread(thread *thread)
{
    posix_memalign((void **) &thread->fpu_area, fpu_get_save_alignment(), fpu_get_save_size());

    if (!thread->fpu_area)
        return -ENOMEM;

    memset(thread->fpu_area, 0, fpu_get_save_size());

    setup_fpu_area(thread->fpu_area);

    /* Note that we don't adjust the addr limit because the thread might be us */
    return 0;
}

} // namespace native

extern "C" void x86_thread_put(thread *t)
{
    thread_put(t);
}
