/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/arch.h>
#include <onyx/clock.h>
#include <onyx/condvar.h>
#include <onyx/cpu.h>
#include <onyx/dpc.h>
#include <onyx/elf.h>
#include <onyx/fpu.h>
#include <onyx/irq.h>
#include <onyx/kcov.h>
#include <onyx/mm/kasan.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/perf_probe.h>
#include <onyx/process.h>
#include <onyx/rwlock.h>
#include <onyx/semaphore.h>
#include <onyx/softirq.h>
#include <onyx/spinlock.h>
#include <onyx/task_switching.h>
#include <onyx/timer.h>
#include <onyx/tss.h>
#include <onyx/vm.h>
#include <onyx/worker.h>

#include <libdict/rb_tree.h>

#include "primitive_generic.h"

static bool is_initialized = false;

void sched_append_to_queue(int priority, unsigned int cpu, thread_t *thread);
void sched_block(thread *thread);
void __sched_append_to_queue(int priority, unsigned int cpu, thread_t *thread);

int sched_rbtree_cmp(const void *t1, const void *t2);
static rb_tree glbl_thread_list = {.cmp_func = sched_rbtree_cmp};
static spinlock glbl_thread_list_lock;

PER_CPU_VAR(spinlock scheduler_lock) = STATIC_SPINLOCK_INIT;
PER_CPU_VAR(thread *thread_queues_head[NUM_PRIO]);
PER_CPU_VAR(thread *thread_queues_tail[NUM_PRIO]);
PER_CPU_VAR(thread *current_thread);

void thread_append_to_global_list(thread *t)
{
    spin_lock(&glbl_thread_list_lock);

    dict_insert_result res = rb_tree_insert(&glbl_thread_list, (void *) (unsigned long) t->id);
    assert(res.inserted == true);
    *res.datum_ptr = t;

    spin_unlock(&glbl_thread_list_lock);
}

void thread_remove_from_list(thread *t)
{
    spin_lock(&glbl_thread_list_lock);

    dict_remove_result res = rb_tree_remove(&glbl_thread_list, (void *) (unsigned long) t->id);
    assert(res.removed != false);

    spin_unlock(&glbl_thread_list_lock);
}

static const char *thread_strings[] = {
    "THREAD_RUNNABLE", "THREAD_INTERRUPTIBLE",   "THREAD_SLEEPING", "THREAD_IDLE",
    "THREAD_DEAD",     "THREAD_UNINTERRUPTIBLE", "THREAD_STOPPED"};

#ifdef CONFIG_SCHED_DUMP_THREADS_MAGIC_SERIAL
#include <onyx/serial.h>
static char buffer[1000];

#define budget_printk(...)                         \
    snprintf(buffer, sizeof(buffer), __VA_ARGS__); \
    platform_serial_write(buffer, strlen(buffer))

#define dump_printk budget_printk

#else

#define dump_printk printk
#endif

bool _dump_thread(const void *key, void *_thread, void *of)
{
    auto thread = (struct thread *) _thread;

    dump_printk("Thread id %d\n", thread->id);

    // FIXME: Fix all instances of cmd_line.c_str() with a race-condition safe way
    if (thread->owner)
        dump_printk("User space thread - owner %s\n", thread->owner->cmd_line.c_str());

    dump_printk("Thread status: %s\n", thread_strings[thread->status]);
    if (thread->status == THREAD_INTERRUPTIBLE || thread->status == THREAD_UNINTERRUPTIBLE)
    {
        registers *regs = (registers *) thread->kernel_stack;
        (void) regs;
#if __x86_64__
        dump_printk("Dumping context. IP = %016lx, RBP = %016lx\n", regs->rip, regs->rbp);
        stack_trace_ex((uint64_t *) regs->rbp);
#endif
    }

    return true;
}

void vterm_panic(void);

void sched_dump_threads(void)
{
    vterm_panic();
    spin_lock(&glbl_thread_list_lock);

    rb_tree_traverse(&glbl_thread_list, _dump_thread, NULL);

    spin_unlock(&glbl_thread_list_lock);
}

thread *thread_get_from_tid(int tid)
{
    spin_lock(&glbl_thread_list_lock);

    void **pp = rb_tree_search(&glbl_thread_list, (const void *) (unsigned long) tid);

    thread *t = NULL;
    if (pp)
    {
        t = (thread *) *pp;
        thread_get(t);
    }

    spin_unlock(&glbl_thread_list_lock);

    return t;
}

FUNC_NO_DISCARD
unsigned long sched_lock(thread *thread)
{
    /* Order of acquisition in order to avoid a deadlock */

    /* 1st - Lock the per-cpu scheduler */
    /* 2nd - Lock the thread */

    assert(thread->cpu < percpu_get_nr_bases());
    spinlock *l = get_per_cpu_ptr_any(scheduler_lock, thread->cpu);

    unsigned long cpu_flags = spin_lock_irqsave(l);
    unsigned long _ = spin_lock_irqsave(&thread->lock);
    (void) _;

    return cpu_flags;
}

void sched_unlock(thread *thread, unsigned long cpu_flags)
{
    spinlock *l = get_per_cpu_ptr_any(scheduler_lock, thread->cpu);

    /* Do the reverse of the above */

    spin_unlock_irqrestore(&thread->lock, CPU_FLAGS_NO_IRQ);
    spin_unlock_irqrestore(l, cpu_flags);
}

thread_t *__sched_find_next(unsigned int cpu)
{
    thread_t *current_thread = get_current_thread();

    if (current_thread)
        assert(spin_lock_held(&current_thread->lock) == false);

    /* Note: These locks are unlocked in sched_load_thread, after loading the thread */
    spinlock *sched_lock = get_per_cpu_ptr_any(scheduler_lock, cpu);
    unsigned long _ = spin_lock_irqsave(sched_lock);
    (void) _;

    thread **thread_queues = (thread **) get_per_cpu_ptr_any(thread_queues_head, cpu);

    if (current_thread)
    {
        unsigned long cpu_flags = spin_lock_irqsave(&current_thread->lock);

        if (current_thread->status == THREAD_RUNNABLE)
        {
            /* Re-append the last thread to the queue */
            __sched_append_to_queue(current_thread->priority, cpu, current_thread);
        }

        spin_unlock_irqrestore(&current_thread->lock, cpu_flags);
    }

    /* Go through the different queues, from the highest to lowest */
    for (int i = NUM_PRIO - 1; i >= 0; i--)
    {
        /* If this queue has a thread, we found a runnable thread! */
        if (thread_queues[i])
        {
            thread_t *ret = thread_queues[i];

            /* Advance the queue by one */
            thread_queues[i] = ret->next_prio;
            if (thread_queues[i])
                ret->prev_prio = nullptr;
            ret->next_prio = nullptr;

            return ret;
        }
    }

    return nullptr;
}

thread_t *sched_find_next()
{
    return __sched_find_next(get_cpu_nr());
}

thread_t *sched_find_runnable(void)
{
    thread_t *thread = sched_find_next();
    if (!thread)
    {
        panic("sched_find_runnable: no runnable thread");
    }
    return thread;
}

PER_CPU_VAR(unsigned long preemption_counter) = 0;

void sched_save_thread(thread *thread, void *stack)
{
    thread->kernel_stack = (uintptr_t *) stack;
#ifdef CONFIG_KASAN
    asan_unpoison_shadow((unsigned long) __builtin_frame_address(0),
                         (char *) stack - (char *) __builtin_frame_address(0));
#endif
    thread->errno_val = errno;

    native::arch_save_thread(thread, stack);
}

#define SCHED_QUANTUM 10

PER_CPU_VAR(uint32_t sched_quantum) = 0;
PER_CPU_VAR(clockevent *sched_pulse);

void sched_decrease_quantum(clockevent *ev)
{
    add_per_cpu(sched_quantum, -1);

    if (get_per_cpu(sched_quantum) == 0)
    {
        thread *curr = get_current_thread();
        curr->flags |= THREAD_NEEDS_RESCHED;
    }

    ev->deadline = clocksource_get_time() + NS_PER_MS;
}

void sched_load_thread(thread *thread, unsigned int cpu)
{
    write_per_cpu(current_thread, thread);

    errno = thread->errno_val;

    native::arch_load_thread(thread, cpu);

    if (thread->owner)
        native::arch_load_process(thread->owner, thread, cpu);

    write_per_cpu(sched_quantum, SCHED_QUANTUM);

    cputime_restart_accounting(thread);

    spin_unlock_irqrestore(get_per_cpu_ptr_any(scheduler_lock, cpu), irq_save_and_disable());
}

extern "C" void asan_unpoison_stack_shadow_ctxswitch(struct registers *regs);

NO_ASAN void sched_load_finish(thread *prev_thread, thread *next_thread)
{
#ifdef CONFIG_KASAN
    asan_unpoison_stack_shadow_ctxswitch((struct registers *) prev_thread->kernel_stack);
#endif
    sched_load_thread(next_thread, get_cpu_nr());

    if (prev_thread)
        prev_thread->flags &= ~THREAD_RUNNING;

    next_thread->flags |= THREAD_RUNNING;

    if (prev_thread && prev_thread->status == THREAD_DEAD && prev_thread->flags & THREAD_IS_DYING)
    {
        /* Finally, kill the thread for good */
        prev_thread->flags &= ~THREAD_IS_DYING;
    }

    native::arch_context_switch(prev_thread, next_thread);
}

unsigned long st_invoked = 0;

extern "C" void *sched_schedule(void *last_stack)
{
    if (!is_initialized || sched_is_preemption_disabled())
    {
        add_per_cpu(sched_quantum, 1);
        return last_stack;
    }

    if (perf_probe_is_enabled_wait())
        perf_probe_try_wait_trace((struct registers *) last_stack);

    thread_t *curr_thread = get_per_cpu(current_thread);

    if (likely(curr_thread))
    {
        bool thread_blocked = curr_thread->status == THREAD_INTERRUPTIBLE ||
                              curr_thread->status == THREAD_UNINTERRUPTIBLE;

        if (thread_blocked && curr_thread->flags & THREAD_ACTIVE)
        {
            write_per_cpu(sched_quantum, 1);
            curr_thread->flags &= ~THREAD_ACTIVE;
            return last_stack;
        }

        curr_thread->flags &= ~THREAD_ACTIVE;

        sched_save_thread(curr_thread, last_stack);

        do_cputime_accounting();
    }

    thread *source_thread = curr_thread;
    irq_save_and_disable();

    curr_thread = sched_find_runnable();
    st_invoked++;

    if (source_thread != curr_thread)
    {
        if (source_thread->owner)
        {
            source_thread->get_aspace()->active_mask.remove_cpu_atomic(get_cpu_nr());
        }
    }

    sched_load_finish(source_thread, curr_thread);
    __builtin_unreachable();

    panic("sched_load_finish returned");
}

void *sched_preempt_thread(void *current_stack)
{
    thread *t = get_current_thread();

    if (t)
        t->flags |= THREAD_ACTIVE;

    COMPILER_BARRIER();

    void *ret = sched_schedule(current_stack);

    if (t)
        t->flags &= ~THREAD_ACTIVE;

    COMPILER_BARRIER();

    return ret;
}

void sched_idle(void *ptr)
{
    (void) ptr;
    /* This function will not do work at all, just idle using hlt or a similar instruction */
    for (;;)
    {
        cpu_sleep();
    }
}

void __sched_append_to_queue(int priority, unsigned int cpu, thread *thread)
{
    MUST_HOLD_LOCK(get_per_cpu_ptr_any(scheduler_lock, cpu));

    assert(thread->status == THREAD_RUNNABLE);

    auto thread_queues = (struct thread **) get_per_cpu_ptr_any(thread_queues_head, cpu);
    thread_t *queue = thread_queues[priority];
    if (!queue)
    {
        thread_queues[priority] = thread;
    }
    else
    {
        while (queue->next_prio)
        {
            assert(queue != thread);
            assert(queue != queue->next_prio);
            queue = queue->next_prio;
        }

        assert(queue != thread);

        queue->next_prio = thread;
        thread->prev_prio = queue;
    }
}

void sched_append_to_queue(int priority, unsigned int cpu, thread_t *thread)
{
    spin_lock(get_per_cpu_ptr_any(scheduler_lock, cpu));

    __sched_append_to_queue(priority, cpu, thread);

    spin_unlock(get_per_cpu_ptr_any(scheduler_lock, cpu));
}

PER_CPU_VAR(unsigned long active_threads) = 0;

unsigned int sched_allocate_processor(void)
{
    unsigned int nr_cpus = get_nr_cpus();
    unsigned int dest_cpu = -1;
    size_t active_threads_min = SIZE_MAX;

    for (unsigned int i = 0; i < nr_cpus; i++)
    {
        unsigned long active_threads_for_cpu = get_per_cpu_any(active_threads, i);
        if (active_threads_for_cpu < active_threads_min)
        {
            dest_cpu = i;
            active_threads_min = active_threads_for_cpu;
        }
    }
    return dest_cpu;
}

void thread_add(thread_t *thread, unsigned int cpu_num)
{
    if (cpu_num == SCHED_NO_CPU_PREFERENCE || cpu_num > get_nr_cpus())
        cpu_num = sched_allocate_processor();

    thread->cpu = cpu_num;
    add_per_cpu_any(active_threads, 1, cpu_num);
    /* Append the thread to the queue */
    sched_append_to_queue(thread->priority, cpu_num, thread);
}

void sched_init_cpu(unsigned int cpu)
{
    thread *t = sched_create_thread(sched_idle, THREAD_KERNEL, nullptr);

    assert(t != nullptr);

    t->priority = SCHED_PRIO_VERY_LOW;
    t->cpu = cpu;

    write_per_cpu_any(current_thread, t, cpu);
    write_per_cpu_any(sched_quantum, SCHED_QUANTUM, cpu);
    write_per_cpu_any(preemption_counter, 0, cpu);

    auto cev = new clockevent;

    assert(cev != nullptr);

    write_per_cpu_any(sched_pulse, cev, cpu);
}

void sched_enable_pulse(void)
{
    clockevent *ev = get_per_cpu(sched_pulse);
    ev->callback = sched_decrease_quantum;
    ev->deadline = clocksource_get_time() + NS_PER_MS;
    ev->flags = CLOCKEVENT_FLAG_ATOMIC | CLOCKEVENT_FLAG_PULSE;
    ev->priv = NULL;

    timer_queue_clockevent(ev);
}

int sched_rbtree_cmp(const void *t1, const void *t2)
{
    int tid0 = (int) (unsigned long) t1;
    int tid1 = (int) (unsigned long) t2;
    return tid1 - tid0;
}

int sched_init(void)
{
    thread *t = sched_create_thread(sched_idle, THREAD_KERNEL, NULL);

    assert(t != NULL);

    t->priority = SCHED_PRIO_NORMAL;
    // sched_start_thread_for_cpu(t, get_cpu_nr());

    write_per_cpu(sched_quantum, SCHED_QUANTUM);
    set_current_thread(t);

    auto cev = new clockevent;

    assert(cev != nullptr);

    write_per_cpu(sched_pulse, cev);

    sched_enable_pulse();

    is_initialized = true;
    return 0;
}

extern "C" void platform_yield(void);

void sched_yield(void)
{
    if (sched_is_preemption_disabled())
    {
        panic("Thread tried to sleep with preemption disabled (preemption counter %ld)",
              (long) sched_get_preempt_counter());
    }

    struct flame_graph_entry *fge = nullptr;
    const bool waiting = get_current_thread()->status == THREAD_INTERRUPTIBLE ||
                         get_current_thread()->status == THREAD_UNINTERRUPTIBLE;
    if (perf_probe_is_enabled_wait() && waiting)
    {
        fge = (struct flame_graph_entry *) alloca(sizeof(*fge));
        perf_probe_setup_wait(fge);
    }

    platform_yield();

    if (fge)
        perf_probe_commit_wait(fge);
}

void sched_sleep_unblock(clockevent *v)
{
    thread *t = (thread *) v->priv;
    thread_wake_up(t);
}

int signal_find(struct thread *thread);

hrtime_t sched_sleep(unsigned long ns)
{
    thread_t *current = get_current_thread();

    clockevent ev;
    ev.callback = sched_sleep_unblock;
    ev.priv = current;

    /* This clockevent can run atomically because it's a simple thread_wake_up,
     * which is safe to call from atomic/interrupt context.
     */
    ev.flags = CLOCKEVENT_FLAG_ATOMIC;
    ev.deadline = clocksource_get_time() + ns;
    timer_queue_clockevent(&ev);

    /* This is a bit of a hack but we need this in cases where we have timeout but we're not
     * supposed to be woken by signals. In this case, wait_for_event_* already set the current
     * state.
     */
    if (current->status == THREAD_RUNNABLE)
        set_current_state(THREAD_INTERRUPTIBLE);

    if (current->status != THREAD_INTERRUPTIBLE || !signal_is_pending())
        sched_yield();

    /* Lets remove the event in the case where we got woken up by a signal or by another thread */
    timer_cancel_event(&ev);

    hrtime_t t1 = clocksource_get_time();
    hrtime_t rem = t1 - ev.deadline;

    /* It's okay if we wake up slightly after we wanted to, just return success */
    if (t1 > ev.deadline)
        rem = 0;

    return -rem;
}

int __sched_remove_thread_from_execution(thread_t *thread, unsigned int cpu)
{
    auto thread_queues = (struct thread **) get_per_cpu_ptr_any(thread_queues_head, cpu);

    for (thread_t *t = thread_queues[thread->priority]; t; t = t->next_prio)
    {
        if (t == thread)
        {
            if (t->prev_prio)
                t->prev_prio->next_prio = t->next_prio;
            else
            {
                thread_queues[thread->priority] = t->next_prio;
            }

            if (t->next_prio)
                t->next_prio->prev_prio = t->prev_prio;
            t->prev_prio = NULL;
            t->next_prio = NULL;

            return 0;
        }
    }

    return -1;
}

int sched_remove_thread_from_execution(thread_t *thread)
{
    unsigned int cpu = thread->cpu;

    spinlock *s = get_per_cpu_ptr_any(scheduler_lock, cpu);
    unsigned long cpu_flags = spin_lock_irqsave(s);

    int st = __sched_remove_thread_from_execution(thread, cpu);

    spin_unlock_irqrestore(s, cpu_flags);

    return st;
}

void sched_remove_thread(thread_t *thread)
{
    sched_remove_thread_from_execution(thread);
    thread_set_state(thread, THREAD_DEAD);
}

void set_current_thread(thread_t *t)
{
    write_per_cpu(current_thread, t);
}

pid_t sys_set_tid_address(pid_t *tidptr)
{
    thread *t = get_current_thread();
    t->ctid = tidptr;
    return t->id;
}

int sys_nanosleep(const timespec *req, timespec *rem)
{
    timespec ts;
    if (copy_from_user(&ts, req, sizeof(timespec)) < 0)
        return -EFAULT;

    if (!timespec_valid(&ts, false))
        return -EINVAL;

    hrtime_t ns = ts.tv_sec * NS_PER_SEC + ts.tv_nsec;

    hrtime_t ns_rem = sched_sleep(ns);

    if (rem)
    {
        ts.tv_sec = ns_rem / NS_PER_SEC;
        ts.tv_nsec = ns_rem % NS_PER_SEC;
        if (copy_to_user(rem, &ts, sizeof(timespec)) < 0)
            return -EFAULT;
    }

    if (rem && signal_is_pending())
        return -EINTR;

    return 0;
}

extern "C" void thread_finish_destruction(void *);

void thread_destroy(struct thread *thread)
{
    /* This function should destroy everything that we can destroy right now.
     * We can't destroy things like the kernel stack or the FPU area, because we'll eventually
     * need to context switch out of here,
     * or you know, we're actually using the kernel stack right now!
     */

    if (thread->owner)
    {
        auto proc = thread->owner;

        proc->remove_thread(thread);

        if (!(thread->sinfo.flags & THREAD_SIGNAL_EXITING))
        {
            /* Don't bother re-routing signals if we're exiting */
            thread->sinfo.reroute_signals(proc);
        }
    }

    /* Remove the thread from the queue */
    sched_remove_thread(thread);

    /* Schedule further thread destruction */
    dpc_work w;
    w.context = thread;
    w.funcptr = thread_finish_destruction;
    dpc_schedule_work(&w, DPC_PRIORITY_MEDIUM);
}

void thread_exit()
{
    // printk("tid %u(%p) dying\n", get_current_thread()->id, get_current_thread()->entry);

    thread *current = get_current_thread();

    kcov_free_thread(current);
    sched_disable_preempt();

    /* We need to switch to the fallback page directory while we can, because
     * we don't know if the current pgd will be destroyed by some other thread.
     */
    vm_switch_to_fallback_pgd();

    current->status = THREAD_DEAD;

    sched_enable_preempt();
    sched_yield();
}

thread *get_thread_for_cpu(unsigned int cpu)
{
    return get_per_cpu_any(current_thread, cpu);
}

bool sched_may_resched(void)
{
    return !(is_in_interrupt() || irq_is_disabled() || sched_is_preemption_disabled());
}

void sched_try_to_resched(thread *thread)
{
    auto current = get_current_thread();
    if (!current)
        return;

    if (current == thread)
        return;

    if (thread->cpu == current->cpu && thread->priority > current->priority)
    {
        if (!sched_may_resched())
        {
            current->flags |= THREAD_NEEDS_RESCHED;
            return;
        }

        /* Just yield, we'll get to execute the thread eventually */
        sched_yield();
    }
    else
    {
        auto other_thread = get_thread_for_cpu(thread->cpu);
        int other_prio = other_thread->priority;
        if (other_prio < thread->priority)
        {
            /* Send a CPU message asking for a resched */
            cpu_send_resched(thread->cpu);
        }
    }
}

void thread_set_state(thread_t *thread, int state)
{
    bool try_resched = false;
    assert(thread != NULL);

    unsigned long cpu_flags = spin_lock_irqsave(&thread->lock);

    if (thread->status == state)
    {
        spin_unlock_irqrestore(&thread->lock, cpu_flags);
        return;
    }

    thread->status = state;

    spin_unlock_irqrestore(&thread->lock, cpu_flags);

    if (try_resched)
        sched_try_to_resched(thread);
}

void __thread_wake_up(thread *thread, unsigned int cpu)
{
    MUST_HOLD_LOCK(&thread->lock);
    MUST_HOLD_LOCK(get_per_cpu_ptr_any(scheduler_lock, cpu));

    /* 1st case: The thread we're "waking up" is running.
     * In this case, just set the status and return, nothing else needed.
     * Note: This can happen when in a scheduler primitive, like a mutex.
     */
    if (get_thread_for_cpu(cpu) == thread)
    {
        thread->status = THREAD_RUNNABLE;
        return;
    }

    if (thread->status == THREAD_RUNNABLE)
        return;

    thread->status = THREAD_RUNNABLE;
    __sched_append_to_queue(thread->priority, cpu, thread);

    if (cpu == get_cpu_nr())
    {
        auto curr = get_current_thread();
        if (thread->priority > curr->priority)
        {
            sched_should_resched();
        }
    }
    else
    {
        auto other_thread = get_thread_for_cpu(thread->cpu);
        int other_prio = other_thread->priority;
        if (other_prio < thread->priority)
        {
            /* Send a CPU message asking for a resched */
            cpu_send_resched(thread->cpu);
        }
    }
}

void thread_wake_up(thread_t *thread)
{
    unsigned long f = sched_lock(thread);

    __thread_wake_up(thread, thread->cpu);

    sched_unlock(thread, f);
}

void sched_block_self(thread *thread, unsigned long fl)
{
    MUST_HOLD_LOCK(get_per_cpu_ptr_any(scheduler_lock, thread->cpu));

    thread->status = THREAD_UNINTERRUPTIBLE;

    spin_unlock_irqrestore(&thread->lock, CPU_FLAGS_NO_IRQ);
    spin_unlock_irqrestore(get_per_cpu_ptr_any(scheduler_lock, thread->cpu), fl);

    sched_yield();
}

void sched_block_other(thread *thread)
{
    panic("not implemented");
}

/* Note: __sched_block returns with everything unlocked */
void __sched_block(thread *thread, unsigned long fl)
{
    auto current = get_current_thread();

    if (current == thread)
    {
        sched_block_self(thread, fl);
    }
    else
    {
        sched_block_other(thread);
    }
}

void sched_block(thread *thread)
{
    unsigned long f = sched_lock(thread);

    __sched_block(thread, f);
}

void sched_sleep_until_wake(void)
{
    thread *thread = get_current_thread();

    sched_block(thread);
}

void sched_start_thread_for_cpu(thread *t, unsigned int cpu)
{
    assert(t != NULL);
    thread_add(t, cpu);
}

void sched_start_thread(thread_t *thread)
{
    sched_start_thread_for_cpu(thread, SCHED_NO_CPU_PREFERENCE);
}

enqueue_thread_generic(condvar, cond);
dequeue_thread_generic(condvar, cond);

void condvar_wait_unlocked(cond *var)
{
    thread_t *current = get_current_thread();

    bool b = irq_is_disabled();

    unsigned long _ = spin_lock_irqsave(&var->llock);
    (void) _;

    unsigned long f = sched_lock(current);

    enqueue_thread_condvar(var, current);

    __spin_unlock(&var->llock);

    __sched_block(current, f);

    if (!b)
        irq_enable();
}

void condvar_wait(cond *var, mutex *mutex)
{
    sched_disable_preempt();

    mutex_unlock(mutex);

    sched_enable_preempt();

    condvar_wait_unlocked(var);

    mutex_lock(mutex);
}

void condvar_signal(cond *var)
{
    unsigned long cpu_flags = spin_lock_irqsave(&var->llock);

    thread_t *thread = var->head;

    if (var->head)
    {
        dequeue_thread_condvar(var, var->head);
        thread_wake_up(thread);
    }

    spin_unlock_irqrestore(&var->llock, cpu_flags);
}

void condvar_broadcast(cond *var)
{
    unsigned long cpu_flags = spin_lock_irqsave(&var->llock);

    while (var->head)
    {
        thread_t *t = var->head;
        if (t->sem_next)
            t->sem_next->sem_prev = NULL;

        var->head = t->sem_next;
        t->sem_next = NULL;

        thread_wake_up(t);
    }

    spin_unlock_irqrestore(&var->llock, cpu_flags);
}

enqueue_thread_generic(sem, semaphore);
dequeue_thread_generic(sem, semaphore);

void sem_init(semaphore *sem, long counter)
{
    sem->counter = 0;
}

void sem_do_slow_path(semaphore *sem)
{
    while (sem->counter == 0)
    {
        thread *thread = get_current_thread();

        unsigned long f = sched_lock(thread);

        enqueue_thread_sem(sem, thread);

        spin_unlock(&sem->lock);

        __sched_block(thread, f);

        spin_lock(&sem->lock);
    }
}

void sem_wait(semaphore *sem)
{
    spin_lock(&sem->lock);

    while (true)
    {
        if (sem->counter > 0)
        {
            sem->counter--;
            break;
        }
        else
        {
            sem_do_slow_path(sem);
        }
    }

    spin_unlock(&sem->lock);
}

static void wake_up(semaphore *sem)
{
    thread_t *target = sem->head;

    dequeue_thread_sem(sem, target);

    thread_wake_up(target);
}

void sem_signal(semaphore *sem)
{
    sem->counter.add_fetch(1, mem_order::release);

    unsigned long cpu_flags = spin_lock_irqsave(&sem->lock);

    if (sem->head)
        wake_up(sem);

    spin_unlock_irqrestore(&sem->lock, cpu_flags);
}

void sched_try_to_resched_if_needed()
{
    thread *current = get_current_thread();

    if (current && sched_needs_resched(current) && sched_may_resched())
    {
        sched_yield();
        current->flags &= ~THREAD_NEEDS_RESCHED;
    }
}

void sched_handle_preempt(bool may_softirq)
{
    if (may_softirq && softirq_pending()) [[unlikely]]
        softirq_handle();
    auto curr = get_current_thread();
    if (curr && curr->flags & THREAD_NEEDS_RESCHED) [[unlikely]]
    {
        sched_yield();
        curr->flags &= ~THREAD_NEEDS_RESCHED;
    }
}

pid_t sys_gettid()
{
    thread *current = get_current_thread();
    /* TODO: Should we emulate actual linux behavior? */
    return current->id;
}

void sched_transition_to_idle()
{
    thread *curr = get_current_thread();
    curr->priority = SCHED_PRIO_VERY_LOW;
    curr->entry(nullptr);
}

int sched_transition_to_user_thread(thread *thread)
{
    int st = 0;
    if ((st = native::arch_transform_into_user_thread(thread)) < 0)
        return st;

    thread->flags &= ~THREAD_KERNEL;
    thread->set_aspace(thread->owner->get_aspace());
    return st;
}

extern "C" unsigned long thread_get_addr_limit(void)
{
    struct thread *t = get_current_thread();
    if (!t) [[unlikely]]
        return VM_KERNEL_ADDR_LIMIT;
    assert(t->addr_limit != 0);
    return t->addr_limit;
}

/**
 * @brief Check if we can sleep (to be used by debugging functions)
 *
 * @return True if we can, else false
 */
bool __can_sleep_internal()
{
    return true;
    if (!get_current_thread() || is_in_panic())
        return true;
    return !sched_is_preemption_disabled() && !irq_is_disabled();
}
