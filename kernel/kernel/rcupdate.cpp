/*
 * Copyright (c) 2023 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 license.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <onyx/clock.h>
#include <onyx/cpumask.h>
#include <onyx/gen/trace_rcupdate.h>
#include <onyx/mm/kasan.h>
#include <onyx/mm/slab.h>
#include <onyx/percpu.h>
#include <onyx/rcupdate.h>
#include <onyx/scheduler.h>
#include <onyx/scoped_lock.h>
#include <onyx/smp.h>
#include <onyx/softirq.h>
#include <onyx/spinlock.h>
#include <onyx/wait.h>

// clang-format off
/* Implementation of classic RCU as in OLS2001 ("Read-Copy Update"), Paul McKenney's RCU
 * dissertation and various early RCU articles on lwn
 * (https://lwn.net/Kernel/Index/#Read-copy-update).
 * Essentially, the algorithm works like this:
 * rcu_read_lock() and rcu_read_unlock() are non-preemptible sections. Context switches are
 * quiescent states. This minimizes reader overhead to a non-atomic pcpu add.
 *
 * When a writer writes to an RCU data structure, it first locks (to serialize against other
 * writers, if needed) changes (some things cannot be done willy nilly, like list removal, as
 * readers are currently traversing), and unlocks. The special sauce here is reclamation. One will
 * call call_rcu() with a destruction function and the rcu_head that was embedded in the object
 * we're reclaiming. That rcu_head will get appended to the 'next' list for the current CPU (more on
 * that later). When a CPU goes through a quiescent state, if 'next' is not empty, it attempts to
 * start a grace period. This behavior allows for batching, as many call_rcu calls can get completed
 * in one scheduler slice.
 *
 * The RCU global state consists of:
   struct rcu_ctrlblk
    {
        spinlock lock;
        1) A lock, protecting rcu_ctrlblk from concurrent changes.
        unsigned long curgen;
        2) The current gen/batch number that is being processed
        unsigned long maxgen;
        3) The maximum gen/batch number that any given CPU on the system is on.
           This is set in rcu_start_batch. If curgen > maxgen, we don't have grace periods to
           process.
        cpumask mask __align_cache;
        4) CPU mask that represents CPUs that have still not gone through a quiescent state since
           the grace period started.
    };
 *
 * Each CPU then has its own local state, rcu_pcpublk:
 *
    struct rcu_pcpublk
    {
        unsigned long gen;
        1) The gen/batch this CPU is on, set in rcu_try_batch.
        struct rcu_cblist current, next;
        2) Singly linked lists of rcu_heads for current callbacks and next callbacks.
           Current callbacks are cbs that *may* need processing right now, if we have gone through
           gen. Next callbacks are queued up in call_rcu and are moved to current when we try to
           start a batch.
    };
 * All the queiscent state code runs under softirq, as soon as possible, actioned by rcu_do_quiesc
 * (called by the scheduler) if need be.
 * To attempt to limit latency, we keep a 'onetime_processed_limit' for a
 * limit of callbacks to process at once, as softirq steals time from scheduler threads.
 * When call_rcu notices that the 'next' list is getting too long, it attempts to force a
 * queiscent state on the current thread as soon as possible.
 *
 * This RCU implementation is annotated with tracepoints you can use to collect data from userspace.
 *
 * Example of a grace period:
 * CPU0                              |                CPU1              |       CPU2
 * call_rcu()                        |                                  |
 *    .                              |                                  |
 * rcu_do_quiesc()                   |                                  |
 *  \- RCU softirq raised            |                                  |
 *    .                              |                                  |
 * softirq_handle()                  |                                  |
 *  \- rcu_work()                    |                                  |
 *   \- rcu_try_batch()              |                                  |
 *    \- GP started, wait-           | rcu_check_quiescent_state()      |
 *       iting for all CPUs.         |  \- 1 is cleared off the mask,   |
 *   \- rcu_check_quiescent_state()  |     0 and 2 pending.             |
 *    \- 0 is cleared off the mask.  |                                  |
 *                                   |                                  | rcu_check_quiescent_state()
 *                                   |                                  |  \- 3 is cleared off the mask
 *                                   |                                  |    \- mask is empty, advancing gen and
 *                                   |                                  |       attempting to start a new batch.
 *                                   |                                  |      \- gen > maxgen, no new GP to be started
 * rcu_do_quiesc()                   |                                  |
 *  \- RCU softirq raised            |                                  |
 *    .                              |                                  |
 * softirq_handle()                  |                                  |
 *  \- rcu_work()                    |                                  |
 *   \- rcu_do_callbacks()           |                                  |
 */
// clang-format on

#define CONFIG_TRACE_RCU 1
#ifndef CONFIG_TRACE_RCU
#define trace_rcu_rcu_do_callbacks_enabled() 0
#undef TRACE_EVENT
#define TRACE_EVENT(...)
#undef TRACE_EVENT_DURATION
#define TRACE_EVENT_DURATION(...)
#endif

/**
 * @brief Global RCU control block data
 *
 * @lock: Lock that protects the whole data structure
 * @curgen: Current generation/batch we are 'on'.
 * @maxgen: Maximum generation on all CPUs.
 * @mask: Mask of CPUs that have not gone through a quiescent state this grace period.
 */
struct rcu_ctrlblk
{
    spinlock lock;
    unsigned long curgen;
    unsigned long maxgen;
    cpumask mask __align_cache;
} __align_cache;

const int onetime_processed_limit = 10000;

static struct rcu_ctrlblk rcp;

struct rcu_cblist
{
    struct rcu_head *head, *tail;
    int nelems;

    [[nodiscard]] bool is_empty()
    {
        return head == nullptr;
    }

    void splice_onto(struct rcu_cblist *dst)
    {
        if (!dst->head)
        {
            dst->head = head;
            dst->tail = tail;
        }
        else if (tail)
        {
            // !empty
            dst->tail->next = head;
            dst->tail = tail;
        }

        dst->nelems += nelems;

        head = tail = nullptr;
        nelems = 0;
    }

    int call_cbs()
    {
        int processed = 0;
        struct rcu_head *it = head;

        while (it)
        {
            if (processed >= onetime_processed_limit)
                break;
            processed++;
            struct rcu_head *next = it->next;
            if (is_kfree_rcu_off((unsigned long) (void *) it->func))
            {
                /* This is a kfree, and ->func represents the offset of the rcu_head with relation
                 * to the real object. */
                void *ptr = (void *) ((unsigned long) it - (unsigned long) it->func);
                kfree(ptr);
            }
            else
                it->func(it);

            it = next;
        }

        nelems -= processed;

        head = it;
        if (head == nullptr)
        {
            tail = nullptr;
            DCHECK(nelems == 0);
        }

        return processed;
    }

    void empty()
    {
        head = tail = nullptr;
        nelems = 0;
    }

    [[gnu::always_inline]] void add(struct rcu_head *h)
    {
        h->next = nullptr;

        if (!head)
            head = h;
        else
            tail->next = h;
        tail = h;
        nelems++;
    }
};

/**
 * @brief RCU percpu data
 *
 * @gen: Generation this CPU is currently on
 * @current: List of callbacks pertaining to this generation
 * @next: List of callbacks pertaining to next generations
 */
struct rcu_pcpublk
{
    unsigned long gen;
    struct rcu_cblist current, next;
};

PER_CPU_VAR(struct rcu_pcpublk rcu_percpu);

/**
 * @brief Attempt to start an RCU batch
 *
 * A batch is only started if we're not in one, or if curgen > maxgen.
 * If it is indeed started, rcp.mask is set to the online cpu mask.
 *
 * @param rpb Current CPU's RCU data
 * @param new_max New maximum generation
 */
static void rcu_start_batch(struct rcu_pcpublk *rpb, unsigned long new_max)
{
    MUST_HOLD_LOCK(&rcp.lock);

    if (rcp.maxgen < new_max)
        rcp.maxgen = new_max;

    // If curgen > maxgen, there are no callbacks to be processed
    if (rcp.curgen > rcp.maxgen)
        return;

    // We may not start a batch if we're already in one
    if (!rcp.mask.is_empty())
        return;

    TRACE_EVENT(rcu_grace_period_begin, rcp.curgen, rcp.maxgen);
    rcp.mask = smp::get_online_cpumask();
}

__always_inline bool rcu_has_callbacks(rcu_pcpublk *rpb)
{
    // Current can be !is_empty for a variety of reasons, including if we tried to start a batch
    // without actually starting it. As such, we can only process callbacks if we have gone through
    // the grace period in ctrlblk.
    return rcp.curgen > rpb->gen && !rpb->current.is_empty();
}

__always_inline bool rcu_has_batch(rcu_pcpublk *rpb)
{
    return rpb->current.is_empty() && !rpb->next.is_empty();
}

static void rcu_do_callbacks(rcu_pcpublk *rpb)
{
    int processed = 0;
    u64 __trace_timestamp = trace_rcu_rcu_do_callbacks_enabled() ? clocksource_get_time() : 0;
    processed = rpb->current.call_cbs();

    if (__trace_timestamp)
        trace_rcu_rcu_do_callbacks(__trace_timestamp, processed);
}

/**
 * @brief Try to start a new RCU batch
 *
 * Attempt to start a new RCU batch by moving up the generation counter
 * and splicing the next list onto current, then calling start_batch.
 * @param rpb Current CPU's RCU data
 */
static void rcu_try_batch(rcu_pcpublk *rpb)
{
    scoped_lock g{rcp.lock};
    rpb->next.splice_onto(&rpb->current);
    // Take our gen counter to the next batch
    rpb->gen = rcp.curgen + 1;
    rcu_start_batch(rpb, rpb->gen);
}

static void rcu_check_quiescent_state(rcu_pcpublk *rpb)
{
    unsigned int curr = get_cpu_nr();

    if (!rcp.mask.is_cpu_set(curr))
        return;

    scoped_lock g{rcp.lock};

    rcp.mask.remove_cpu(curr);
    TRACE_EVENT(rcu_ack_grace_period);

    if (rcp.mask.is_empty())
    {
        TRACE_EVENT(rcu_grace_period_end);
        // Attempt to start a new batch by incrementing the current gen and calling rcu_start_batch
        // with maxgen.
        rcp.curgen++;
        rcu_start_batch(rpb, rcp.maxgen);
    }
}

/**
 * @brief Do RCU work (softirq routine)
 *
 */
void rcu_work()
{
    TRACE_EVENT_DURATION(rcu_rcu_work);
    // This runs under softirq
    rcu_pcpublk *rpb = get_per_cpu_ptr(rcu_percpu);

    if (rcu_has_callbacks(rpb))
        rcu_do_callbacks(rpb);
    if (rcu_has_batch(rpb))
        rcu_try_batch(rpb);
    rcu_check_quiescent_state(rpb);
}

/**
 * @brief Handle a quiescent state
 * Raises the softirq if required.
 *
 */
void rcu_do_quiesc()
{
    TRACE_EVENT(rcu_rcu_do_quiesc);
    rcu_pcpublk *rpb = get_per_cpu_ptr(rcu_percpu);

    /* Check if we have RCU work to do, i.e:
     * 1) global gen > gen and current isn't empty - we have went through a quiescent state and have
     *    callbacks to process.
     * 2) current is empty but next isn't - we have callbacks to process, so we're going to try and
     *    start a batch if possible
     * 3) our cpu is set in rcp.mask - we have a quiescent state to process
     */

    if (rcu_has_callbacks(rpb) || rcu_has_batch(rpb) || rcp.mask.is_cpu_set(get_cpu_nr()))
        softirq_raise(SOFTIRQ_VECTOR_RCU);
}

void call_rcu(struct rcu_head *head, void (*callback)(struct rcu_head *))
{
    TRACE_EVENT(rcu_call_rcu);

    head->next = nullptr;
    head->func = callback;

    auto flags = irq_save_and_disable();

    rcu_pcpublk *rpb = get_per_cpu_ptr(rcu_percpu);
    rpb->next.add(head);

    if (rpb->next.nelems >= onetime_processed_limit)
    {
        // Attempt to force a queiscent state as soon as possible in this thread,
        // as the next list is getting too long. This is done to minimize latency and grace periods.
        sched_should_resched();
    }

    irq_restore(flags);
}

void synchronize_rcu()
{
    struct sync_token
    {
        struct rcu_head head;
        int wake;
    } token;

    token.wake = 0;

    call_rcu(&token.head, [](struct rcu_head *head) {
        struct sync_token *token = container_of(head, struct sync_token, head);
        token->wake = 1;
        wake_address((void *) token);
    });

    wait_for(
        &token,
        [](void *ptr) -> bool {
            struct sync_token *token = (struct sync_token *) ptr;
            return token->wake == 1;
        },
        WAIT_FOR_FOREVER, 0);

    DCHECK(token.wake == 1);
}

void __kfree_rcu(struct rcu_head *head, unsigned long off)
{
    kasan_record_kfree_rcu(head, off);
    head->func = (void (*)(struct rcu_head *))(void *) off;
    head->next = nullptr;

    auto flags = irq_save_and_disable();

    rcu_pcpublk *rpb = get_per_cpu_ptr(rcu_percpu);
    rpb->next.add(head);

    if (rpb->next.nelems >= onetime_processed_limit)
    {
        // Attempt to force a queiscent state as soon as possible in this thread,
        // as the next list is getting too long. This is done to minimize latency and grace periods.
        sched_should_resched();
    }

    irq_restore(flags);
}
