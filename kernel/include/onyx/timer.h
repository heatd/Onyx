/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_TIMER_H
#define _KERNEL_TIMER_H

#include <stdbool.h>
#include <stdint.h>

#include <onyx/clock.h>
#include <onyx/list.h>
#include <onyx/spinlock.h>

#include <linux/lockdep_types.h>

__BEGIN_CDECLS
void udelay(unsigned int us);
void ndelay(unsigned int ns);
__END_CDECLS

#define CLOCKEVENT_FLAG_ATOMIC  (1 << 0) /* Can run in IRQ context */
#define CLOCKEVENT_FLAG_PENDING (1 << 1) /* Is waiting to run under softirq context */
#define CLOCKEVENT_FLAG_PULSE \
    (1 << 2) /* Automatically requeue the same struct (that was modified by the cb) */
#define CLOCKEVENT_FLAG_POISON (1 << 3)

struct timer;
struct clockevent;

void timer_cancel_event(struct clockevent *ev);
void timer_mod(struct clockevent *ev, hrtime_t future);
struct clockevent
{
    hrtime_t deadline;
    void *priv;
    unsigned int flags;
    void (*callback)(struct clockevent *ev);
    struct list_head list_node;
    struct timer *timer;
    struct lockdep_map dep_map;

#ifdef __cplusplus
    clockevent() : deadline{0}, priv{nullptr}, flags{0}, callback{nullptr}, timer{nullptr}
    {
        INIT_LIST_HEAD(&list_node);
    }

    ~clockevent()
    {
        if (timer)
            timer_cancel_event(this);
    }
#endif
};

static inline void __clockevent_init(struct clockevent *ev, void (*cb)(struct clockevent *),
                                     unsigned int flags)
{
    ev->deadline = 0;
    ev->priv = NULL;
    ev->flags = flags;
    ev->callback = cb;
    ev->timer = NULL;
    INIT_LIST_HEAD(&ev->list_node);
}

#ifdef CONFIG_LOCKDEP
void clockevent_init_lockdep(struct clockevent *ev, void (*cb)(struct clockevent *),
                             unsigned int flags, const char *name, struct lock_class_key *key);

#define clockevent_init(ev, cb, flags)                       \
    do                                                       \
    {                                                        \
        static struct lock_class_key __key;                  \
        clockevent_init_lockdep(ev, cb, flags, #ev, &__key); \
    } while (0)
#else
#define clockevent_init(ev, cb, flags) __clockevent_init(ev, cb, flags)
#endif

static inline void clockevent_kill(struct clockevent *ev)
{
    WRITE_ONCE(ev->timer, NULL);
}

#define TIMER_NEXT_EVENT_NOT_PENDING UINT64_MAX

struct timer
{
    const char *name;
    hrtime_t next_event;
    void *priv;
    struct list_head event_list;
    struct spinlock event_list_lock;
    struct clockevent *executing;
    void (*set_oneshot)(hrtime_t in_future);
    void (*set_periodic)(unsigned long freq);
    void (*disable_timer)(void);
    void (*on_event)(void);
};

struct timer *platform_get_timer(void);
void timer_queue_clockevent(struct clockevent *ev);
void timer_handle_events(struct timer *t);

static inline bool clockevent_active(struct clockevent *ev)
{
    return READ_ONCE(ev->timer) != NULL;
}

#endif
