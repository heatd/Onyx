/*
 * Copyright (c) 2019 - 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/scoped_lock.h>
#include <onyx/softirq.h>
#include <onyx/spinlock.h>
#include <onyx/timer.h>
#include <onyx/user.h>
#include <onyx/vm.h>

#include <linux/list.h>
#include <linux/lockdep.h>
#include <uapi/time.h>

static void __timer_queue_clockevent(struct clockevent *ev, struct timer *timer)
{
    lockdep_assert_held(&timer->event_list_lock);

    if (ev->flags & CLOCKEVENT_FLAG_POISON)
        panic("Tried to queue clockevent that's already queued");

    ev->timer = timer;

    list_add_tail(&ev->list_node, &timer->event_list);

    atomic_and_relaxed(ev->flags, ~CLOCKEVENT_FLAG_PENDING);
    ev->flags |= CLOCKEVENT_FLAG_POISON;

    if (timer->next_event > ev->deadline)
    {
        timer->next_event = ev->deadline;
        timer->set_oneshot(ev->deadline);
    }
}

void timer_queue_clockevent(struct clockevent *ev)
{
    auto timer = platform_get_timer();

    scoped_lock<spinlock, true> g{timer->event_list_lock};
    __timer_queue_clockevent(ev, timer);
}

void timer_disable(struct timer *t)
{
    if (t->disable_timer)
        t->disable_timer();
}

struct timer_iterator
{
    hrtime_t now;
    bool atomic;
};

static struct clockevent *timer_get_expired(struct timer *t, struct timer_iterator *iter)
{
    unsigned long cpu_flags = spin_lock_irqsave(&t->event_list_lock);
    struct clockevent *ret = NULL;
    hrtime_t lowest = UINT64_MAX;
    bool raised = false;

    list_for_every_safe (&t->event_list)
    {
        struct clockevent *ev = container_of(l, struct clockevent, list_node);
        const bool pulse = ev->flags & CLOCKEVENT_FLAG_PULSE;

        if (ev->deadline > iter->now)
        {
            lowest = min(lowest, ev->deadline);
            continue;
        }

        /* Atomic events can be safely handled under the timer lock */
        if (ev->flags & CLOCKEVENT_FLAG_ATOMIC)
        {
            ev->callback(ev);
            if (!pulse)
            {
                ev->flags &= ~CLOCKEVENT_FLAG_POISON;
                list_del_init(&ev->list_node);
                ev->timer = NULL;
            }
            else
            {
                lowest = min(lowest, ev->deadline);
            }
        }
        else if (iter->atomic)
        {
            /* We can't handle most timers in atomic context. Schedule a softirq. */
            if (!raised)
                softirq_raise(SOFTIRQ_VECTOR_TIMER);
            raised = true;
        }
        else
        {
            /* We _can_ handle this, lets do so. */
            list_del_init(&ev->list_node);
            if (!pulse)
                atomic_and_relaxed(ev->flags, ~(CLOCKEVENT_FLAG_PENDING | CLOCKEVENT_FLAG_POISON));

            t->executing = ev;
            ret = ev;
            break;
        }
    }

    if (lowest == UINT64_MAX)
    {
        t->next_event = TIMER_NEXT_EVENT_NOT_PENDING;
        timer_disable(t);
    }
    else
    {
        t->next_event = lowest;
        t->set_oneshot(lowest);
    }
    spin_unlock_irqrestore(&t->event_list_lock, cpu_flags);
    return ret;
}

static inline bool clockevent_pending(struct clockevent *ev)
{
    return !list_is_empty(&ev->list_node);
}

#ifndef CONFIG_LOCKDEP
#define lockdep_copy_map(to, from) \
    do                             \
    {                              \
    } while (0)
#endif

void timer_handle_events(struct timer *t)
{
    struct timer_iterator iter = {
        .now = clocksource_get_time(),
        .atomic = irq_is_disabled(),
    };
    unsigned long cpu_flags;
    bool is_pulse;
    struct clockevent *ev;

    while ((ev = timer_get_expired(t, &iter)))
    {
#ifdef CONFIG_LOCKDEP
        struct lockdep_map copy;

        lockdep_copy_map(&copy, &ev->dep_map);
#endif
        is_pulse = ev->flags & CLOCKEVENT_FLAG_PULSE;

        lock_map_acquire(&copy);
        ev->callback(ev);
        lock_map_release(&copy);

        cpu_flags = spin_lock_irqsave(&t->event_list_lock);
        t->executing = NULL;

        /* Note that if the clockevent is pulse, this event needs to be alive (i.e unfreed, but
         * could be RCU-freed) _after_ the callback runs. It's simply a restriction we have to deal
         * with. */
        if (is_pulse && ev->flags & CLOCKEVENT_FLAG_PULSE)
        {
            ev->flags &= ~CLOCKEVENT_FLAG_POISON;
            __timer_queue_clockevent(ev, t);
        }
        spin_unlock_irqrestore(&t->event_list_lock, cpu_flags);
    }
}

static struct timer *lock_timer(struct clockevent *ev, unsigned long *cpu_flags)
{
    struct timer *timer;

    for (;;)
    {
        timer = READ_ONCE(ev->timer);
        /* No timer? we're good. */
        if (!timer)
            return NULL;
        *cpu_flags = spin_lock_irqsave(&timer->event_list_lock);
        if (ev->timer == timer)
            break;
        spin_unlock_irqrestore(&timer->event_list_lock, *cpu_flags);
    }

    return timer;
}

static struct timer *timer_cancel_event_try(struct clockevent *ev)
{
    struct timer *timer, *ret;
    unsigned long cpu_flags;

    timer = lock_timer(ev, &cpu_flags);
    if (!timer)
        return NULL;

    /* Running? Lets spin on this */
    ret = timer;
    if (timer->executing == ev)
        goto out;

    ret = NULL;
    if (clockevent_pending(ev))
    {
        atomic_and_relaxed(ev->flags, ~CLOCKEVENT_FLAG_POISON);
        list_del_init(&ev->list_node);
        ev->timer = NULL;
    }

out:
    spin_unlock_irqrestore(&timer->event_list_lock, cpu_flags);
    return ret;
}

static void timer_spin_pending(struct timer *timer, struct clockevent *ev)
{
    while (READ_ONCE(timer->executing) == ev)
        cpu_relax();
}

/**
 * @brief Try to cancel a clockevent
 *
 * @param ev Event to cancel
 * @retval true if still cancelled
 * @return false if running
 */
bool timer_cancel_try(struct clockevent *ev)
{
    return timer_cancel_event_try(ev) == nullptr;
}

void timer_cancel_event(struct clockevent *ev)
{
    struct timer *timer;

    lock_map_acquire(&ev->dep_map);
    lock_map_release(&ev->dep_map);

    do
    {
        timer = timer_cancel_event_try(ev);
        if (timer)
            timer_spin_pending(timer, ev);
    } while (timer);
}

static struct timer *lock_timer_mod(struct clockevent *ev, unsigned long *cpu_flags)
{
    struct timer *timer, *read;

    for (;;)
    {
        read = timer = READ_ONCE(ev->timer);
        /* No timer? lock current (we're queuing it, this is a mod operation) */
        if (!timer)
            timer = platform_get_timer();
        *cpu_flags = spin_lock_irqsave(&timer->event_list_lock);
        if (ev->timer == read)
            break;
        spin_unlock_irqrestore(&timer->event_list_lock, *cpu_flags);
    }

    return timer;
}

void timer_mod(struct clockevent *ev, hrtime_t future)
{
    struct timer *timer;
    unsigned long cpu_flags;

    timer = lock_timer_mod(ev, &cpu_flags);

    /* Note: ev->timer is stable as long as we hold the corresponding lock */
    if (clockevent_pending(ev))
    {
        DCHECK(timer == ev->timer);
        /* Bump the timestamp. TODO: getting a satisfactory next-event is impossible. This makes it
         * so we get spurious events. */
        ev->deadline = future;
        if (future < timer->next_event)
        {
            timer->next_event = future;
            timer->set_oneshot(future);
        }
    }
    else
    {
        /* Not queued. Queue it. Note that timer_mod() does not guard against the timer being
         * concurrently executing. That is up to the user to avoid (or deal with the
         * consequences). */
        ev->deadline = future;
        __timer_queue_clockevent(ev, timer);
    }

    spin_unlock_irqrestore(&timer->event_list_lock, cpu_flags);
}

#ifdef CONFIG_LOCKDEP
void clockevent_init_lockdep(struct clockevent *ev, void (*cb)(struct clockevent *),
                             unsigned int flags, const char *name, struct lock_class_key *key)
{
    __clockevent_init(ev, cb, flags);
    lockdep_init_map(&ev->dep_map, name, key, 0);
}
#endif

void itimer_init(struct process *p)
{
    int timer_whichs[3] = {ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF};
    int i = 0;

    for (auto &it : p->sig->timers)
    {
        it.p = p;
        it.which = timer_whichs[i++];
        it.ev = {};
        it.armed = false;
        spinlock_init(&it.lock);
        it.interval_delta = 0;
    }
}

static bool valid_itimer_which(int which)
{
    /* TODO: Add other timers */
    if (which != ITIMER_REAL)
        return false;

    return true;
}

int sys_getitimer(int which, struct itimerval *curr_value)
{
    if (!valid_itimer_which(which))
        return -EINVAL;

    itimerval v{};

    struct process *current = get_current_process();

    auto &timer = current->sig->timers[which];

    scoped_lock guard{timer.lock};

    if (timer.armed)
    {
        hrtime_to_timeval(timer.interval_delta, &v.it_interval);

        hrtime_delta_t delta = timer.ev.deadline - clocksource_get_time();

        /* Clamp the delta to 1 if it's negative or 0, since it may be
         * undefined or just mislead the caller into thinking the timer isn't armed.
         */

        if (delta <= 0)
            delta = 1;

        hrtime_to_timeval(delta, &v.it_value);
    }

    if (copy_to_user(curr_value, &v, sizeof(v)) < 0)
        return -EFAULT;

    return 0;
}

int itimer_which_to_signal(itimer *t)
{
    switch (t->which)
    {
        case ITIMER_REAL:
            return SIGALRM;
        case ITIMER_VIRTUAL:
            return SIGVTALRM;
        case ITIMER_PROF:
            return SIGPROF;
        default:
            __builtin_unreachable();
    }
}

void itimer_callback(clockevent *ev)
{
    itimer *it = static_cast<itimer *>(ev->priv);
    auto interval = it->interval_delta;

    ev->deadline = clocksource_get_time() + interval;

    auto signal = itimer_which_to_signal(it);

    kernel_raise_signal(signal, it->p, 0, nullptr);
}

int itimer::arm(hrtime_t interval, hrtime_t initial)
{
    scoped_lock guard{lock};

    if (armed)
    {
        timer_cancel_event(&ev);
    }

    interval_delta = interval;
    clockevent_init(&ev, itimer_callback, (interval_delta ? CLOCKEVENT_FLAG_PULSE : 0));
    ev.priv = this;
    ev.deadline = clocksource_get_time() + initial;
    timer_queue_clockevent(&ev);

    armed = true;

    return 0;
}

int itimer::disarm()
{
    scoped_lock g{lock};

    if (armed)
    {
        if (!timer_cancel_try(&ev))
        {
            /* We can't form a dependency loop between signal_lock, itimer::lock and timer
             * cancelling (waiting). Thus, back out and try again later. */
            return -EAGAIN;
        }
    }

    return 0;
}

int itimer_disarm(struct itimer *it)
{
    return it->disarm();
}

int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value)
{
    if (!valid_itimer_which(which))
        return -EINVAL;

    int st = 0;

    itimerval v{};
    if (copy_from_user(&v, new_value, sizeof(v)) < 0)
        return -EFAULT;

    if (old_value)
    {
        /* For now, calling the syscall directly works okay */
        st = sys_getitimer(which, old_value);
        if (st < 0)
            return st;
    }

    hrtime_t interval_ns, initial_ns;

    if (!timeval_valid(&v.it_interval, false) || !timeval_valid(&v.it_value, false))
        return -EINVAL;

    interval_ns = timeval_to_hrtime(&v.it_interval);
    initial_ns = timeval_to_hrtime(&v.it_value);

    struct process *current = get_current_process();

    auto &timer = current->sig->timers[which];

    if (!initial_ns)
    {
        while ((st = timer.disarm()) == -EAGAIN)
            cpu_relax();
    }
    else
        st = timer.arm(interval_ns, initial_ns);

    return st;
}
