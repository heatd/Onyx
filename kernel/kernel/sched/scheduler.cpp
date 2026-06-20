/*
 * Copyright (c) 2016 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
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
#include <onyx/atomic.h>
#include <onyx/block/blk_plug.h>
#include <onyx/clock.h>
#include <onyx/condvar.h>
#include <onyx/cpu.h>
#include <onyx/dpc.h>
#include <onyx/elf.h>
#include <onyx/fpu.h>
#include <onyx/gen/trace_sched.h>
#include <onyx/irq.h>
#include <onyx/kcov.h>
#include <onyx/mm/kasan.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/perf_probe.h>
#include <onyx/process.h>
#include <onyx/rcupdate.h>
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
#include <linux/lockdep.h>

#include "primitive_generic.h"
#include "scheduler_priv.h"

/*
 * Scale factor for scaled integers used to count %cpu time and load avgs.
 *
 * The number of CPU `tick's that map to a unique `%age' can be expressed
 * by the formula (1 / (2 ^ (FSHIFT - 11))).  Since the intermediate
 * calculation is done with 64-bit precision, the maximum load average that can
 * be calculated is approximately 2^32 / FSCALE.
 *
 * For the scheduler to maintain a 1:1 mapping of CPU `tick' to `%age',
 * FSHIFT must be at least 11.  This gives a maximum load avg of 2 million.
 */
#define FSHIFT 11 /* bits to right of fixed binary point */
#define FSCALE (1 << FSHIFT)

/*
 * Constants for averages over 1, 5, and 15 minutes
 * when sampling at 5 second intervals.
 */
static const u64 cexp[3] = {
    1884, /* exp(-1/12) */
    2014, /* exp(-1/60) */
    2036, /* exp(-1/180) */
};

static bool is_initialized = false;

void sched_append_to_queue(int priority, unsigned int cpu, thread_t *thread);
void sched_block(thread *thread);
static void __sched_append_to_queue(int priority, unsigned int cpu, thread_t *thread);
static void ___sched_append_to_queue(int priority, unsigned int cpu, struct thread *thread);
unsigned int sched_allocate_processor(struct cpumask mask);

int sched_rbtree_cmp(const void *t1, const void *t2);
static rb_tree glbl_thread_list = {.cmp_func = sched_rbtree_cmp};
static DEFINE_SPINLOCK(glbl_thread_list_lock);

static PER_CPU_VAR(struct sched_rq cpu_rq) = {
    .lock = STATIC_SPINLOCK_INIT(cpu_rq.lock),
};

PER_CPU_VAR(thread *current_thread);
PER_CPU_VAR(unsigned int tasks_in_queues);

static inline struct sched_rq *this_rq(void)
{
    return get_per_cpu_ptr(cpu_rq);
}

#define lockdep_assert_sched_lock() lockdep_assert_held(&this_rq()->lock)

static inline struct sched_rq *sched_rq_for(unsigned int cpu)
{
    return get_per_cpu_ptr_any(cpu_rq, cpu);
}

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

    dump_printk("Thread id %d (refs %lu)\n", thread->id, thread->refcount);

    // FIXME: Fix all instances of cmd_line.c_str() with a race-condition safe way
    if (thread->owner)
        dump_printk("User space thread - owner %s (pid %d, task %p)\n",
                    thread->owner->cmd_line.c_str(), thread->owner->pid_, thread->owner);

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
    unsigned long cpu_flags, _;
    struct sched_rq *rq;

    for (;;)
    {
        unsigned int cpu = READ_ONCE(thread->cpu);
        assert(cpu < get_nr_cpus());
        rq = sched_rq_for(cpu);
        cpu_flags = spin_lock_irqsave(&rq->lock);
        _ = spin_lock_irqsave(&thread->lock);
        if (thread->cpu == cpu)
            break;
        (void) _;
        spin_unlock_irqrestore(&thread->lock, CPU_FLAGS_NO_IRQ);
        spin_unlock_irqrestore(&rq->lock, cpu_flags);
    }

    return cpu_flags;
}

void sched_unlock(thread *thread, unsigned long cpu_flags)
{
    /* Do the reverse of the above */
    spin_unlock_irqrestore(&thread->lock, CPU_FLAGS_NO_IRQ);
    spin_unlock_irqrestore(&sched_rq_for(thread->cpu)->lock, cpu_flags);
}

PER_CPU_VAR(long runnable_delta) = 0;

extern void sched_idle(void *);

static thread_t *sched_steal_job(unsigned int cpu)
{
    struct sched_rq *rq;

    for (unsigned int i = 0; i < get_nr_cpus(); i++)
    {
        if (i == cpu)
            continue;
        if (other_cpu_get(tasks_in_queues, i) <= 1)
            continue;
        rq = sched_rq_for(i);
        if (spin_try_lock(&rq->lock))
            continue;

        for (int j = NUM_PRIO - 1; j >= 0; j--)
        {
            /* If this queue has a thread, we found a runnable thread! */
            for (struct thread *thr = rq->thread_queues_head[j]; thr != NULL; thr = thr->next_prio)
            {
                if (!cpumask_is_set(&thr->task_affinity, cpu))
                    continue;
                if (thr->entry == sched_idle || __atomic_load_n(&thr->on_cpu, __ATOMIC_ACQUIRE))
                    continue;
                /* Advance the queue by one */
                if (thr->prev_prio)
                    thr->prev_prio->next_prio = thr->next_prio;
                else
                    rq->thread_queues_head[j] = thr->next_prio;
                if (thr->next_prio)
                    thr->next_prio->prev_prio = thr->prev_prio;
                thr->prev_prio = thr->next_prio = NULL;
                other_cpu_add(tasks_in_queues, -1, i);
                add_per_cpu(tasks_in_queues, 1);
                WARN_ON(thr->cpu != i);
                SCHED_DEBUG_WARN_ON(!(READ_ONCE(thr->flags) & THREAD_IN_QUEUE));
                thr->cpu = cpu;
                atomic_or_relaxed(thr->flags, THREAD_SNOOPED);
                spin_unlock(&rq->lock);
                return thr;
            }
        }

        spin_unlock(&rq->lock);
    }

    return nullptr;
}

static void maybe_kick_cpu(struct thread *thread)
{
    unsigned int cpu = thread->cpu;
    struct thread *remote;

    rcu_read_lock();
    remote = get_thread_for_cpu(cpu);
    if (READ_ONCE(remote->priority) < thread->priority)
    {
        if (cpu == get_cpu_nr())
            sched_should_resched();
        else
            cpu_send_resched(cpu);
    }
    rcu_read_unlock();
}

/**
 * @brief Migrate a thread
 *
 * @param curr Thread to migrate
 * @return true if we stayed on the same CPU, else false.
 */
static bool sched_do_migrate(struct thread *curr)
{
    struct sched_rq *rq;
    struct cpumask mask;
    unsigned int target;
    unsigned long flags;

    rq = this_rq();

retry:
    lockdep_assert_held(&rq->lock);
    lockdep_assert_held(&curr->lock);

    /* Ugh. This is annoying. Lets take a snapshot of the mask, and calculate a target CPU for that.
     * Holding the current scheduler locks stabilizes the affinity.
     */
    mask = curr->task_affinity;

    /* Prefer current. */
    if (cpumask_is_set(&mask, get_cpu_nr()))
        target = get_cpu_nr();
    else
        target = sched_allocate_processor(mask);
    /* Unlock locks. */
    spin_unlock_irqrestore(&curr->lock, CPU_FLAGS_NO_IRQ);
    spin_unlock_irqrestore(&rq->lock, CPU_FLAGS_NO_IRQ);

    /* Re-lock sched locks for the new CPU */
    rq = sched_rq_for(target);
    flags = spin_lock_irqsave(&rq->lock);
    flags = spin_lock_irqsave(&curr->lock);

    if (!cpumask_equal(&mask, &curr->task_affinity))
        goto retry;
    /* Great! target is indeed part of mask. mask is stabilized. Add it to the queue and unlock. */
    __sched_append_to_queue(curr->priority, target, curr);
    curr->cpu = target;
    /* No point in kicking ourselves, kick remote only. */
    if (target != get_cpu_nr())
        maybe_kick_cpu(curr);
    spin_unlock_irqrestore(&curr->lock, CPU_FLAGS_NO_IRQ);

    if (target != get_cpu_nr())
    {
        spin_unlock_irqrestore(&rq->lock, CPU_FLAGS_NO_IRQ);
        flags = spin_lock_irqsave(&this_rq()->lock);
    }

    (void) flags;
    return false;
}

/**
 * @brief (Attempt to) requeue the thread
 *
 * @param curr Thread to requeue (must be current)
 * @return True if requeued back to the current CPU, else false (can be on another CPU).
 */
static bool sched_requeue_task(struct thread *curr)
{
    unsigned int curr_cpu = get_cpu_nr();

    lockdep_assert_sched_lock();
    lockdep_assert_held(&curr->lock);

    if (curr->status != THREAD_RUNNABLE)
    {
        add_per_cpu(runnable_delta, -1);
        spin_unlock_irqrestore(&curr->lock, CPU_FLAGS_NO_IRQ);
        return false;
    }

    /* This is likely - the cpu is currently in the CPU mask. In which case, just re-append and
     * bail. */
    if (likely(cpumask_is_set(&curr->task_affinity, curr_cpu)))
    {
        ___sched_append_to_queue(curr->priority, curr_cpu, curr);
        spin_unlock_irqrestore(&curr->lock, CPU_FLAGS_NO_IRQ);
        return true;
    }

    return sched_do_migrate(curr);
}

thread_t *__sched_find_next(unsigned int cpu)
{
    struct sched_rq *rq = sched_rq_for(cpu);
    thread_t *current_thread = get_current_thread();

    lockdep_assert_not_held(&current_thread->lock);

    /* Note: These locks are unlocked in sched_load_thread, after loading the thread */
    unsigned long _ = spin_lock_irqsave(&rq->lock);
    _ = spin_lock_irqsave(&current_thread->lock);
    (void) _;

    if (!sched_requeue_task(current_thread))
        add_per_cpu(tasks_in_queues, -1);

    lockdep_assert_held(&rq->lock);
    /* Go through the different queues, from the highest to lowest */
    for (int i = NUM_PRIO - 1; i >= 0; i--)
    {
        /* If this queue has a thread, we found a runnable thread! */
        if (rq->thread_queues_head[i])
        {
            thread_t *ret = rq->thread_queues_head[i];

            if (ret->entry == sched_idle)
            {
                thread_t *stolen = sched_steal_job(cpu);
                if (stolen)
                    return stolen;
            }

            /* Advance the queue by one */
            rq->thread_queues_head[i] = ret->next_prio;
            if (rq->thread_queues_head[i])
                rq->thread_queues_head[i]->prev_prio = nullptr;
            ret->next_prio = ret->prev_prio = nullptr;
            return ret;
        }
    }

    return nullptr;
}

thread_t *sched_find_next()
{
    return __sched_find_next(get_cpu_nr());
}

static void dump_thread(struct thread *thread);

thread_t *sched_find_runnable(void)
{
    thread_t *thread = sched_find_next();
    if (!thread)
    {
        panic("sched_find_runnable: no runnable thread");
    }
    atomic_and_relaxed(thread->flags, ~THREAD_IN_QUEUE);
    WARN_ON(thread->cpu != get_cpu_nr());
    if (get_current_thread() != thread)
    {
        if (WARN_ON(thread->on_cpu))
            dump_thread(thread);
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

#define SCHED_QUANTUM                    10
#define SCHED_TICKS_BETWEEN_LOADAVG_CALC 5000

PER_CPU_VAR(uint32_t sched_quantum) = 0;
PER_CPU_VAR(u16 ticks_to_loadavg_calc) = SCHED_TICKS_BETWEEN_LOADAVG_CALC;
PER_CPU_VAR(clockevent *sched_pulse);

unsigned long avenrun[3];
unsigned long nrun = 0;

unsigned long sched_get_runnable(void)
{
    unsigned long nr_runnable = 0;

    for (unsigned int i = 0; i < get_nr_cpus(); i++)
        nr_runnable += other_cpu_get(runnable_delta, i);

    return nr_runnable;
}

void calc_avenrun()
{
    unsigned long nr_runnable = sched_get_runnable();
    if ((long) nr_runnable < 0)
        panic("calc_avenrun: negative nr runnable %ld", nr_runnable);
    nrun = nr_runnable;

    for (int i = 0; i < 3; i++)
        avenrun[i] = (avenrun[i] * cexp[i] + nr_runnable * FSCALE * (FSCALE - cexp[i])) >> FSHIFT;
}

static void sched_acct_system(hrtime_t time)
{
    enum kcputimes type = CPUTIME_SYSTEM;
    if (softirq_is_handling())
        type = CPUTIME_SOFTIRQ;
    kcputime_add(type, time);
}

void sched_decrease_quantum(clockevent *ev)
{
    unsigned int quantum = get_per_cpu(sched_quantum);
    if (quantum > 0)
        add_per_cpu(sched_quantum, -1);
    struct thread *current = get_current_thread();
    if (current)
    {
        if (in_kernel_space_regs(current->regs))
        {
            if (current->entry == sched_idle)
                kcputime_add(CPUTIME_IDLE, NS_PER_MS);
            else
                sched_acct_system(NS_PER_MS);
            current->cputime_info.system_time += NS_PER_MS;
        }
        else
        {
            kcputime_add(CPUTIME_USER, NS_PER_MS);
            get_current_thread()->cputime_info.user_time += NS_PER_MS;
        }
    }

    if (quantum == 1)
        atomic_or_relaxed(current->flags, THREAD_NEEDS_RESCHED);

    if (get_cpu_nr() == 0)
    {
        add_per_cpu(ticks_to_loadavg_calc, -1);
        if (get_per_cpu(ticks_to_loadavg_calc) == 0)
        {
            write_per_cpu(ticks_to_loadavg_calc, SCHED_TICKS_BETWEEN_LOADAVG_CALC);
            calc_avenrun();
        }
    }

    ev->deadline = clocksource_get_time() + NS_PER_MS;
}

static void dump_thread(struct thread *thread)
{
    struct registers *regs;

    pr_warn("thread id %u entry %pS status %u flags %u\n", thread->id, thread->entry,
            thread->status, thread->flags);
    if (thread->owner)
        pr_warn("belonging to %s[%d], last switched %lu ms ago\n", thread->owner->comm,
                thread->owner->pid_,
                (clocksource_get_time() - thread->owner->last_switch_time) / NS_PER_MS);
    regs = (struct registers *) thread->kernel_stack;
    (void) regs;
#ifdef CONFIG_DEBUG_SCHEDULER
    pr_warn("last seen at ip %pS, last switch-in %lu ms ago, last finish "
            "switch %lu ms ago\n",
            (void *) regs->rip, (clocksource_get_time() - thread->last_switch_in) / NS_PER_MS,
            (clocksource_get_time() - thread->last_finish) / NS_PER_MS);
    pr_warn("raw ts: in %lu swtch %lu finish %lu\n", thread->last_switch_in / NS_PER_US,
            thread->owner ? thread->owner->last_switch_time / NS_PER_US : 0,
            thread->last_finish / NS_PER_US);
#endif
}

void sched_load_thread(struct thread *prev, thread *thread, unsigned int cpu)
{
    struct mm_address_space *mm = prev->active_mm ?: prev->aspace;
    struct sched_rq *rq = sched_rq_for(cpu);

    CHECK(prev->on_cpu);
    if (prev != thread)
    {
        CHECK(thread != get_current_thread());
        if (WARN_ON(thread->on_cpu))
        {
            pr_warn("thread %p has on_cpu %d for cpu %u (curr %u)\n", thread, thread->on_cpu,
                    thread->cpu, cpu);
            dump_thread(thread);
        }
    }

    spin_release(&rq->lock.dep_map, _THIS_IP_);
    write_per_cpu(current_thread, thread);
    spin_acquire(&rq->lock.dep_map, 0, 0, _THIS_IP_);
    spin_unlock_irqrestore(&rq->lock, irq_save_and_disable());
    errno = thread->errno_val;

    WRITE_ONCE(thread->on_cpu, 1);
#ifdef CONFIG_DEBUG_SCHEDULER
    thread->last_switch_in = clocksource_get_time();
    prev->last_finish = clocksource_get_time();
#endif
    native::arch_load_thread(thread, cpu);

    if (!(thread->flags & THREAD_KERNEL))
        DCHECK(thread->owner);

    if (thread->owner)
    {
        /* Clear ourselves from the mm mask and drop the active_mm, if we had one */
        if (mm != thread->owner->get_aspace())
        {
            native::arch_load_process(thread->owner, thread, cpu);
            cpumask_unset_atomic(&mm->active_mask, cpu);
        }
    }
    else
    {
        /* Skip switching mm's by keeping this one active */
        if (thread != prev)
        {
            CHECK(thread->active_mm == NULL);
            thread->active_mm = mm;
            mmgrab(mm);
        }
    }

    if (thread != prev && prev->active_mm)
    {
        mmdrop(mm);
        prev->active_mm = NULL;
    }

    write_per_cpu(sched_quantum, SCHED_QUANTUM);

    cputime_restart_accounting(thread);
}

extern "C" void asan_unpoison_stack_shadow_ctxswitch(struct registers *regs);

static PER_CPU_VAR(unsigned long nr_ctx_switches);
unsigned long sched_total_ctx_switches(void)
{
    unsigned long total = 0;
    for (unsigned int i = 0; i < get_nr_cpus(); i++)
        total += get_per_cpu_any(nr_ctx_switches, i);
    return total;
}

NO_ASAN void sched_load_finish(thread *prev_thread, thread *next_thread)
{
    CHECK(irq_is_disabled());
#ifdef CONFIG_KASAN
    asan_unpoison_stack_shadow_ctxswitch((struct registers *) prev_thread->kernel_stack);
#endif
    sched_load_thread(prev_thread, next_thread, get_cpu_nr());

    inc_per_cpu(nr_ctx_switches);
    if (prev_thread)
        atomic_and_relaxed(prev_thread->flags, ~THREAD_RUNNING);

    atomic_or_relaxed(next_thread->flags, THREAD_RUNNING);

    if (prev_thread)
    {
        auto status = READ_ONCE(prev_thread->status);
        if (status == THREAD_DEAD && READ_ONCE(prev_thread->flags) & THREAD_IS_DYING)
            /* Finally, kill the thread for good */
            prev_thread->flags &= ~THREAD_IS_DYING;
    }

    CHECK(irq_is_disabled());
    native::arch_context_switch(prev_thread, next_thread);
}

extern "C" void finish_switch(struct thread *prev)
{
    WARN_ON(prev == get_current_thread());
#ifdef CONFIG_DEBUG_SCHEDULER
    prev->last_finish = clocksource_get_time();
#endif
    __atomic_store_n(&prev->on_cpu, 0, __ATOMIC_RELEASE);
    if (prev->status == THREAD_DEAD)
        thread_put(prev);
}

extern "C" void *sched_schedule(void *last_stack)
{
    if (!is_initialized)
    {
        add_per_cpu(sched_quantum, 1);
        return last_stack;
    }

    thread_t *curr_thread = get_per_cpu(current_thread);

    if (sched_is_preemption_disabled())
    {
        add_per_cpu(sched_quantum, 1);
        if (likely(curr_thread))
            sched_needs_resched(curr_thread);
        return last_stack;
    }

    if (perf_probe_is_enabled_wait())
        perf_probe_try_wait_trace((struct registers *) last_stack);

    if (likely(curr_thread))
    {
        struct process *current = curr_thread->owner;
        int status = READ_ONCE(curr_thread->status);
        bool thread_blocked = status == THREAD_INTERRUPTIBLE || status == THREAD_UNINTERRUPTIBLE ||
                              status == THREAD_STOPPED;

        if (thread_blocked)
        {
            if (curr_thread->flags & THREAD_ACTIVE)
            {
                write_per_cpu(sched_quantum, 1);
                curr_thread->flags &= ~THREAD_ACTIVE;
                return last_stack;
            }
            trace_sched_block();
        }

        if (current)
        {
            if (thread_blocked)
                current->nvcsw++;
            else
                current->nivcsw++;
            current->last_switch_time = clocksource_get_time();
        }

        curr_thread->flags &= ~THREAD_ACTIVE;

        sched_save_thread(curr_thread, last_stack);

        do_cputime_accounting();
    }

    rcu_do_quiesc();

    thread *source_thread = curr_thread;
    irq_save_and_disable();

    curr_thread = sched_find_runnable();

    if (source_thread != curr_thread)
    {
        trace_sched_slice_end();
        trace_sched_slice_begin(curr_thread->id, curr_thread->owner ? curr_thread->owner->pid_ : 0,
                                curr_thread->owner ? curr_thread->owner->comm : NULL);
    }
    else
    {
        write_per_cpu(sched_quantum, SCHED_QUANTUM);
        spin_unlock_irqrestore(&this_rq()->lock, CPU_FLAGS_NO_IRQ);
        irq_enable();
        return last_stack;
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

static void ___sched_append_to_queue(int priority, unsigned int cpu, struct thread *thread)
{
    struct sched_rq *rq = sched_rq_for(cpu);

    lockdep_assert_held(&rq->lock);
    assert(READ_ONCE(thread->status) == THREAD_RUNNABLE);

    thread_t *queue = rq->thread_queues_head[priority];
    if (!queue)
        rq->thread_queues_head[priority] = thread;
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

    thread->next_prio = NULL;
    atomic_or_relaxed(thread->flags, THREAD_IN_QUEUE);
    atomic_and_relaxed(thread->flags, ~(THREAD_SNOOPED | THREAD_FASTWAKE));
}

static void __sched_append_to_queue(int priority, unsigned int cpu, struct thread *thread)
{
    add_per_cpu_any(tasks_in_queues, 1, cpu);
    ___sched_append_to_queue(priority, cpu, thread);
}

void sched_append_to_queue(int priority, unsigned int cpu, thread_t *thread)
{
    struct sched_rq *rq = sched_rq_for(cpu);
    unsigned long flags = spin_lock_irqsave(&rq->lock);

    __sched_append_to_queue(priority, cpu, thread);
    spin_unlock_irqrestore(&rq->lock, flags);
    add_per_cpu(runnable_delta, 1);
}

unsigned int sched_allocate_processor(struct cpumask mask)
{
    unsigned int dest_cpu = -1;
    size_t active_threads_min = SIZE_MAX;

    if (WARN_ON(mask.is_empty()))
        return 0;

    mask &= smp::get_online_cpumask();
    mask.for_every_cpu([&dest_cpu, &active_threads_min](unsigned int i) -> bool {
        unsigned long active_threads_for_cpu = get_per_cpu_any(tasks_in_queues, i);
        if (active_threads_for_cpu < active_threads_min)
        {
            dest_cpu = i;
            active_threads_min = active_threads_for_cpu;
        }
        return true;
    });

    return dest_cpu;
}

static void thread_add(thread_t *thread, unsigned int cpu_num)
{
    struct thread *remote;

    thread->cpu = cpu_num;
    trace_sched_cpu_assign(thread->id, thread->owner ? thread->owner->pid_ : 0,
                           thread->owner ? thread->owner->comm : NULL, thread->cpu);
    /* Append the thread to the queue */
    sched_append_to_queue(thread->priority, cpu_num, thread);
    rcu_read_lock();
    remote = get_thread_for_cpu(cpu_num);
    if (remote && remote->priority < thread->priority)
    {
        if (cpu_num == get_cpu_nr())
            sched_should_resched();
        else
            cpu_send_resched(cpu_num);
    }

    rcu_read_unlock();
}

void sched_init_cpu(unsigned int cpu)
{
    thread *t = sched_create_thread(sched_idle, THREAD_KERNEL, nullptr);

    assert(t != nullptr);

    t->priority = SCHED_PRIO_VERY_LOW;
    t->cpu = cpu;
    t->on_cpu = 1;
    t->task_affinity = cpumask::one(cpu);

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

    clockevent_init(ev, sched_decrease_quantum, CLOCKEVENT_FLAG_ATOMIC | CLOCKEVENT_FLAG_PULSE);
    ev->deadline = clocksource_get_time() + NS_PER_MS;
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
    t->on_cpu = 1;
    t->task_affinity = cpumask::one(get_cpu_nr());
    t->cpu = get_cpu_nr();
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
    struct thread *curr = get_current_thread();
    if (sched_is_preemption_disabled())
    {
        panic("Thread tried to sleep with preemption disabled (preemption counter %ld)",
              (long) sched_get_preempt_counter());
    }

    struct flame_graph_entry *fge = nullptr;
    int curstatus = READ_ONCE(curr->status);
    const bool waiting = curstatus == THREAD_INTERRUPTIBLE || curstatus == THREAD_UNINTERRUPTIBLE;

    if (waiting)
    {
        /* Flush the plug if we're going to sleep */
        if (curr->plug)
            blk_flush_plug(curr->plug);

        if (perf_probe_is_enabled_wait())
        {
            fge = (struct flame_graph_entry *) alloca(sizeof(*fge));
            perf_probe_setup_wait(fge);
        }

        if (curr->flags & THREAD_WORKQUEUE)
            wq_worker_sleeping(curr);
    }

    platform_yield();

    if (fge)
        perf_probe_commit_wait(fge);
    if (waiting)
    {
        if (curr->flags & THREAD_WORKQUEUE)
            wq_worker_running(curr);
    }
}

void sched_sleep_unblock(clockevent *v)
{
    thread *t = (thread *) v->priv;
    thread_wake_up(t);
}

int signal_find(struct thread *thread);

hrtime_t sched_sleep(unsigned long ns)
{
    thread_t *curthr = get_current_thread();

    clockevent ev;
    /* This clockevent can run atomically because it's a simple thread_wake_up,
     * which is safe to call from atomic/interrupt context.
     */
    clockevent_init(&ev, sched_sleep_unblock, CLOCKEVENT_FLAG_ATOMIC);
    ev.priv = curthr;

    /* This is a bit of a hack but we need this in cases where we have timeout but we're not
     * supposed to be woken by signals. In this case, wait_for_event_* already set the current
     * state.
     */
    int status = READ_ONCE(curthr->status);
    if (status == THREAD_RUNNABLE)
    {
        set_current_state(THREAD_INTERRUPTIBLE);
        status = THREAD_INTERRUPTIBLE;
    }

    ev.deadline = clocksource_get_time() + ns;
    timer_queue_clockevent(&ev);

    if (status != THREAD_INTERRUPTIBLE || !signal_is_pending())
        sched_yield();

    set_current_state(THREAD_RUNNABLE);
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
    struct sched_rq *rq = sched_rq_for(cpu);

    for (thread_t *t = rq->thread_queues_head[thread->priority]; t; t = t->next_prio)
    {
        if (t == thread)
        {
            if (t->prev_prio)
                t->prev_prio->next_prio = t->next_prio;
            else
            {
                rq->thread_queues_head[thread->priority] = t->next_prio;
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
    /* XXX DO WE NEED THIS??? */
    unsigned int cpu = thread->cpu;
    struct sched_rq *rq = sched_rq_for(cpu);

    unsigned long cpu_flags = spin_lock_irqsave(&rq->lock);
    int st = __sched_remove_thread_from_execution(thread, cpu);
    spin_unlock_irqrestore(&rq->lock, cpu_flags);
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
    struct process *curr = get_current_process();
    curr->ctid = tidptr;
    return curr->pid_;
}

int sys_nanosleep(const timespec *req, timespec *rem)
{
    timespec ts;
    if (copy_from_user(&ts, req, sizeof(timespec)) < 0)
        return -EFAULT;

    if (!timespec_valid(&ts, false))
        return -EINVAL;

    hrtime_t ns = ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
    if (ns == 0)
        return 0;

    hrtime_t ns_rem = sched_sleep(ns);

    if (rem)
    {
        ts.tv_sec = ns_rem / NS_PER_SEC;
        ts.tv_nsec = ns_rem % NS_PER_SEC;
        if (copy_to_user(rem, &ts, sizeof(timespec)) < 0)
            return -EFAULT;
    }

    if (signal_is_pending())
        return -ERESTART_RESTARTBLOCK;

    return 0;
}

int sys_clock_nanosleep(clockid_t clock, int flags, const struct timespec *req,
                        struct timespec *rem)
{
    if (clock != CLOCK_MONOTONIC)
        return -ENOSYS;
    return sys_nanosleep(req, rem);
}

extern "C" void thread_finish_destruction(struct rcu_head *);

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
    }

    /* Remove the thread from the queue */
    sched_remove_thread(thread);
    call_rcu(&thread->rcu_head, thread_finish_destruction);
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

    WRITE_ONCE(current->status, THREAD_DEAD);

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

static bool __thread_wake_up(thread *thread, unsigned int cpu, unsigned int state,
                             unsigned int flags)
{
    struct sched_rq *rq = sched_rq_for(cpu);
    unsigned int new_cpu;
    unsigned int status;

    MUST_HOLD_LOCK(&thread->lock);
    lockdep_assert_held(&rq->lock);
    smp_mb__after_spinlock();

    status = READ_ONCE(thread->status);
    if ((status != state && state != -1U) || status == THREAD_RUNNABLE)
    {
        /* Not the state we were expecting. oops. */
        /* XXX task state tech debt makes us so we need to special case stopped... */
        if (!(flags & TWU_TOLERATE_STOPPED) || status != THREAD_STOPPED)
            return false;
    }
    /* 1st case: The thread we're "waking up" is running.
     * In this case, just set the status and return, nothing else needed.
     * Note: This can happen when in a scheduler primitive, like a mutex.
     */
    if (get_thread_for_cpu(cpu) == thread)
    {
        atomic_or_relaxed(thread->flags, THREAD_FASTWAKE);
        WRITE_ONCE(thread->status, THREAD_RUNNABLE);
        return true;
    }

    if (__atomic_load_n(&thread->on_cpu, __ATOMIC_ACQUIRE) > 0)
        new_cpu = cpu;
    else
        new_cpu = sched_allocate_processor(thread->task_affinity);
    WRITE_ONCE(thread->status, THREAD_RUNNABLE);
    if (new_cpu != cpu)
    {
        /* Release the locks and reacquire them in proper order, then reappend to the queue. */
        thread->cpu = new_cpu;
        spin_unlock_irqrestore(&thread->lock, CPU_FLAGS_NO_IRQ);
        spin_unlock_irqrestore(&rq->lock, CPU_FLAGS_NO_IRQ);
        unsigned long _ = sched_lock(thread);
        (void) _;
        WARN_ON(thread->cpu != new_cpu);
        cpu = new_cpu;
    }

    __sched_append_to_queue(thread->priority, cpu, thread);
    add_per_cpu(runnable_delta, 1);

    if (cpu == get_cpu_nr())
    {
        auto curr = get_current_thread();
        if (thread->priority > curr->priority)
            sched_should_resched();
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

    return true;
}

bool thread_wake_up_try(thread_t *thread, unsigned int state, unsigned int flags)
{
    bool did;

    unsigned long f = sched_lock(thread);
    did = __thread_wake_up(thread, thread->cpu, state, flags);
    sched_unlock(thread, f);
    return did;
}

void thread_wake_up(thread_t *thread)
{
    thread_wake_up_try(thread, -1, 0);
}

void sched_block_self(thread *thread, unsigned long fl)
{
    lockdep_assert_sched_lock();

    thread->status = THREAD_UNINTERRUPTIBLE;

    spin_unlock_irqrestore(&thread->lock, CPU_FLAGS_NO_IRQ);
    spin_unlock_irqrestore(&this_rq()->lock, fl);
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

void sched_start_thread(thread_t *thread)
{
    unsigned int cpu = sched_allocate_processor(task_cpu_affinity(thread));
    thread_add(thread, cpu);
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

void condvar_wait(cond *var, mutex *mutex) REQUIRES(mutex)
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
    spinlock_init(&sem->lock);
}

static void sem_do_slow_path(semaphore *sem, unsigned long flags)
{
    while (sem->counter == 0)
    {
        thread *thread = get_current_thread();
        unsigned long f = sched_lock(thread);
        enqueue_thread_sem(sem, thread);
        spin_unlock_irqrestore(&sem->lock, flags);
        __sched_block(thread, f);
        flags = spin_lock_irqsave(&sem->lock);
    }
}

void sem_wait(semaphore *sem)
{
    unsigned long flags = spin_lock_irqsave(&sem->lock);

    while (true)
    {
        if (sem->counter > 0)
        {
            sem->counter--;
            break;
        }
        else
        {
            sem_do_slow_path(sem, flags);
        }
    }

    spin_unlock_irqrestore(&sem->lock, flags);
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
    if (curr && READ_ONCE(curr->flags) & THREAD_NEEDS_RESCHED &&
        READ_ONCE(curr->status) == THREAD_RUNNABLE) [[unlikely]]
    {
        sched_yield();
        atomic_and_relaxed(curr->flags, ~THREAD_NEEDS_RESCHED);
    }
}

pid_t sys_gettid()
{
    return get_current_process()->pid_;
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
    vm_load_aspace(thread->owner->get_aspace(), get_cpu_nr());
    if (thread->active_mm)
    {
        mmdrop(thread->active_mm);
        thread->active_mm = NULL;
    }

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

extern process *first_process;

/**
 * @brief Check if we can sleep (to be used by debugging functions)
 *
 * @return True if we can, else false
 */
bool __can_sleep_internal()
{
    if (!get_current_thread() || is_in_panic() || !first_process)
        return true;
    return !sched_is_preemption_disabled() && !irq_is_disabled();
}

static int copy_cpumask_from_user(const void *cpu_set, size_t cpusetsize, struct cpumask *mask)
{
    size_t copy_size = min(cpusetsize, sizeof(struct cpumask));

    /* If copying less bytes, clear the whole cpumask (this could be optimized, with some care) */
    if (copy_size < sizeof(struct cpumask))
        *mask = cpumask{};

    if (copy_from_user(mask, cpu_set, copy_size))
        return -EFAULT;
    return 0;
}

/**
 * @brief Set a task's affinity
 *
 * @param thread Task for which to set affinity
 * @param mask Affinity mask.
 * @return 0 on success, negative error numbers.
 * In case the caller needs to sched_yield() (e.g we need to migrate ourselves), this function
 * returns 1 (which should be passed back to userspace as 0).
 */
int task_set_affinity(struct thread *thread, struct cpumask mask)
{
    bool migrating_current = thread == get_current_thread();
    bool migrating;
    unsigned long flags;

    mask &= smp::get_online_cpumask();
    if (mask.is_empty())
        return -EINVAL;

    flags = sched_lock(thread);
    thread->task_affinity = mask;
    migrating = !cpumask_is_set(&mask, thread->cpu);
    if (!migrating)
        migrating_current = false;
    /* Ugh, we can't migrate immediately if it isn't running, but is runnable. yuck. fix? */
    if (migrating && !migrating_current && thread->on_cpu)
        cpu_send_resched(thread->cpu);
    sched_unlock(thread, flags);

    /* Hint that the caller needs to sched_yield() */
    return migrating && migrating_current;
}

static bool task_may_set_affinity(struct process *current, struct process *target)
{
    uid_t euid = current->cred.euid;
    return euid == 0 || euid == target->cred.euid || euid == target->cred.ruid;
}

int sys_sched_setaffinity(pid_t pid, size_t cpusetsize, const void *cpu_set)
{
    struct process *task, *current;
    struct cpumask new_mask;
    int err;

    err = copy_cpumask_from_user(cpu_set, cpusetsize, &new_mask);
    if (err)
        return err;

    rcu_read_lock();
    current = get_current_process();
    if (!pid)
        task = current;
    else
    {
        task = get_process_from_pid_noref(pid);
        if (!task)
        {
            err = -ESRCH;
            goto out;
        }
    }

    err = -EPERM;
    if (task_may_set_affinity(current, task))
        err = task_set_affinity(task->thr, new_mask);
out:
    rcu_read_unlock();
    if (err == 1)
    {
        sched_yield();
        err = 0;
    }

    return err;
}

int sys_sched_getaffinity(pid_t pid, size_t cpusetsize, void *cpu_set)
{
    struct process *task;
    struct cpumask mask;
    unsigned long flags;

    /* The passed size should be unsigned long aligned, since the cpu_set is de-facto of type
     * unsigned long */
    if (cpusetsize & (sizeof(unsigned long) - 1))
        return -EINVAL;

    rcu_read_lock();
    if (!pid)
        task = get_current_process();
    else
    {
        task = get_process_from_pid_noref(pid);
        if (!task)
        {
            rcu_read_unlock();
            return -ESRCH;
        }
    }

    flags = spin_lock_irqsave(&task->thr->lock);
    mask = task->thr->task_affinity;
    spin_unlock_irqrestore(&task->thr->lock, flags);
    rcu_read_unlock();

    /* Linux man-page verbiage (and, indeed, the implementation) allows us to not require a full
     * cpumask from userspace (i.e if we only have 8 bits, a byte would do). However, we don't
     * really do that kind of tracking, and this level of micro-optimization is useless. */
    if (cpusetsize < sizeof(cpumask))
        return -EINVAL;

    if (copy_to_user(cpu_set, &mask, sizeof(cpumask)))
        return -EFAULT;

    return sizeof(cpumask);
}

int sys_getcpu(unsigned int *cpu, unsigned int *node, void *cache)
{
    unsigned int curcpu = get_cpu_nr();

    /* The syscall itself has this cache argument, which has been ignored in Linux (since 2.6.x).
     * Let's also not use it. */
    (void) cache;
    if (cpu && copy_to_user(cpu, &curcpu, sizeof(curcpu)))
        return -EFAULT;

    if (node)
    {
        /* No NUMA support yet. everything is node 0 */
        unsigned int n = 0;
        if (copy_to_user(node, &n, sizeof(n)))
            return -EFAULT;
    }
    return 0;
}
