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
#ifdef __cplusplus
extern "C" {
#endif

uint64_t get_tick_count();
uint64_t get_microseconds();

void udelay(unsigned int us);
void ndelay(unsigned int ns);

typedef void (*timer_callback)(void *context);

struct timer_event
{
	uint64_t future_timestamp;
	timer_callback callback;
	void *context;
	bool can_run_in_irq;
};

uint64_t timer_in_future(uint64_t offset);
void timer_handle_pending_events(void);
bool add_timer_event(struct timer_event* event);

struct timer
{
	const char *name;
	hrtime_t next_event;
	void (*set_oneshot)(hrtime_t in_future);
	void (*set_periodic)(unsigned long freq);
	void (*disable_timer)(void);
	void (*on_event)(void);
};

#ifdef __cplusplus
}
#endif
#endif
