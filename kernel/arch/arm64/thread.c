/*
 * Copyright (c) 2022 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#define DEFINE_CURRENT
#include <onyx/err.h>
#include <onyx/process.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>
#include <onyx/vm.h>

static int curr_id = 1;
#define kernel_stack_size 0x4000

void thread_setup_stack(struct thread *thread, bool is_user, const registers_t *regs)
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
        kregs->sp = (uint64_t) thread->kernel_stack;
    }

    pr_warn("pc: %lx\n", kregs->pc);
    thread->kernel_stack = (uint64_t *) kregs;
}

void kernel_thread_start(void *arg)
{
    struct thread *thread = get_current_thread();

    thread->entry(arg);
    thread_exit();
}

void thread_finish_destruction(struct rcu_head *rcu_head)
{
    struct thread *thread = container_of(rcu_head, struct thread, rcu_head);

    /* Destroy the kernel stack */
    unsigned long stack_base = ((unsigned long) thread->kernel_stack_top) - kernel_stack_size;

    vfree((void *) stack_base);
    /* Free the fpu area */
    free(thread->fpu_area);

    thread_remove_from_list(thread);

    memset_explicit(&thread->lock, 0x80, sizeof(struct spinlock));
    ((volatile struct thread *) thread)->canary = THREAD_DEAD_CANARY;
    /* Free the thread */
    free(thread);
}

struct thread *sched_spawn_thread(registers_t *regs, unsigned int flags, void *tp)
{
    struct thread *new_thread = thread_alloc();

    if (!new_thread)
        return NULL;

    new_thread->id = __atomic_fetch_add(&curr_id, 1, __ATOMIC_RELAXED);
    new_thread->flags = flags;
    new_thread->canary = THREAD_STRUCT_CANARY;
    new_thread->fpu_area = NULL;

    bool is_user = !(flags & THREAD_KERNEL);
    unsigned long pages = 4;
    void *original_entry = (void *) regs->pc;

    if (is_user)
    {
        new_thread->fpu_area = (unsigned char *) fpu_allocate_state();
        if (!new_thread->fpu_area)
            goto error;

        memset(new_thread->fpu_area, 0, fpu_get_save_size());
        setup_fpu_area(new_thread->fpu_area);

        new_thread->addr_limit = VM_USER_ADDR_LIMIT;
        new_thread->owner = current;
        new_thread->aspace = current->address_space;
    }
    else
    {
        new_thread->addr_limit = VM_KERNEL_ADDR_LIMIT;

        // Set trampoline as the starting RIP
        regs->pc = (unsigned long) kernel_thread_start;
        new_thread->aspace = &kernel_address_space;
    }

    cputime_info_init(new_thread);

    new_thread->refcount = 1;
    new_thread->kernel_stack =
        (uintptr_t *) vmalloc(pages, VM_TYPE_STACK, VM_READ | VM_WRITE, GFP_KERNEL);

    if (!new_thread->kernel_stack)
    {
        goto error;
    }

    new_thread->kernel_stack =
        (uintptr_t *) (((char *) new_thread->kernel_stack + kernel_stack_size));
    new_thread->kernel_stack_top = new_thread->kernel_stack;

    thread_setup_stack(new_thread, is_user, regs);
    new_thread->tpidr = (unsigned long) tp;

    thread_append_to_global_list(new_thread);
    new_thread->priority = SCHED_PRIO_NORMAL;

    if (!is_user)
    {
        // thread_setup_stack makes the entry = %rip, but in this case, it's not true since we're
        // using a trampoline. Therefore, we need to save the original rip up there so
        // we can restore it.
        new_thread->entry = (thread_callback_t) (original_entry);
    }

    return new_thread;

error:
    if (new_thread->fpu_area)
        free(new_thread->fpu_area);

    free(new_thread);
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
    info->base = (void *) vm_pick_stack_location();
    void *ptr = vm_mmap(info->base, info->length, PROT_WRITE | PROT_READ,
                        MAP_ANON | MAP_PRIVATE | MAP_FIXED | MAP_GROWSDOWN, NULL, 0);
    if (IS_ERR(ptr))
        return PTR_ERR(ptr);
    CHECK(ptr == info->base);
    info->top = (void *) ((unsigned long) ptr + info->length);

    return 0;
}

void arm64_thread_put(struct thread *t)
{
    thread_put(t);
}

unsigned long arm64_current_stack_top(void)
{
    return (unsigned long) get_current_thread()->kernel_stack_top;
}
