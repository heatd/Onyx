/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>

#include <onyx/timer.h>
#include <onyx/spinlock.h>
#include <onyx/panic.h>

extern "C"
void timer_queue_clockevent(struct clockevent *ev)
{
	auto timer = platform_get_timer();

	spin_lock_irqsave(&timer->event_list_lock);

	if(ev->flags & CLOCKEVENT_FLAG_POISON)
		panic("Tried to queue clockevent that's already queued");

	list_add_tail(&ev->list_node, &timer->event_list);

	ev->flags |= CLOCKEVENT_FLAG_POISON;

	if(timer->next_event > ev->deadline)
	{
		timer->next_event = ev->deadline;
		timer->set_oneshot(ev->deadline);
	}

	spin_unlock_irqrestore(&timer->event_list_lock);
}

extern "C"
void timer_disable(struct timer *t)
{
	if(t->disable_timer)
		t->disable_timer();
}

extern "C"
void timer_handle_events(struct timer *t)
{
	auto current_time = clocksource_get_time();

	spin_lock_irqsave(&t->event_list_lock);

	hrtime_t lowest = UINT64_MAX;

	list_for_every_safe(&t->event_list)
	{
		struct clockevent *ev = container_of(l, struct clockevent, list_node);
		if(ev->deadline > current_time)
		{
			lowest = lowest < ev->deadline ? lowest : ev->deadline;
			continue;
		}

		if(ev->flags & CLOCKEVENT_FLAG_ATOMIC)
		{
			ev->callback(ev);
			if(!(ev->flags & CLOCKEVENT_FLAG_PULSE))
			{
				ev->flags &= ~CLOCKEVENT_FLAG_POISON;
				list_remove(&ev->list_node);
			}
			else
			{
				lowest = lowest < ev->deadline ? lowest : ev->deadline;
			}
		}
		else
			ev->flags |= CLOCKEVENT_FLAG_PENDING;
	}

	if(lowest == UINT64_MAX)
	{
		t->next_event = TIMER_NEXT_EVENT_NOT_PENDING;
		timer_disable(t);
	}
	else
	{
		t->next_event = lowest;
		t->set_oneshot(lowest);
	}
	
	spin_unlock_irqrestore(&t->event_list_lock);
}