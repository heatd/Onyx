/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_TIMER_H
#define _KERNEL_TIMER_H

#include <stdint.h>
#include <stdbool.h>

#include <onyx/clock.h>
#include <onyx/list.h>
#include <onyx/spinlock.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t get_tick_count();
uint64_t get_microseconds();

void udelay(unsigned int us);
void ndelay(unsigned int ns);

#define CLOCKEVENT_FLAG_ATOMIC			(1 << 0) 	/* Can run in IRQ context */	
#define CLOCKEVENT_FLAG_PENDING			(1 << 1)	/* Is waiting to run under softirq context */
#define CLOCKEVENT_FLAG_PULSE			(1 << 2)	/* Automatically requeue the same struct (that was modified by the cb) */
#define CLOCKEVENT_FLAG_POISON			(1 << 3)

struct timer;

struct clockevent
{
	/* This lock protects the whole structure from concurrent access */
	struct spinlock lock;
	hrtime_t deadline;
	void *priv;
	unsigned int flags;
	void (*callback)(struct clockevent *ev);
	struct list_head list_node;
	struct timer *timer;
};

#define TIMER_NEXT_EVENT_NOT_PENDING			UINT64_MAX

struct timer
{
	const char *name;
	hrtime_t next_event;
	void *priv;
	struct list_head event_list;
	struct spinlock event_list_lock;
	void (*set_oneshot)(hrtime_t in_future);
	void (*set_periodic)(unsigned long freq);
	void (*disable_timer)(void);
	void (*on_event)(void);
};

struct timer *platform_get_timer(void);
void timer_queue_clockevent(struct clockevent *ev);
void timer_handle_events(struct timer *t);
void timer_remove_event(struct clockevent *ev);

#ifdef __cplusplus
}
#endif
#endif
