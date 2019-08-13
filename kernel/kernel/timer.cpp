/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>

#include <onyx/timer.h>
#include <onyx/list.hpp>
#include <onyx/spinlock.h>
#include <onyx/panic.h>

static LinkedList<timer_event*> pending_list;
static spinlock list_lock;

/* Ported from Carbon, improved and C-ified */

extern "C"
bool add_timer_event(timer_event* event)
{
	timer_event *ev = new timer_event;
	if(!ev)
		return false;
	memcpy(ev, event, sizeof(timer_event));

	spin_lock_irqsave(&list_lock);
	bool st = pending_list.Add(ev);

	if(!st)
		delete ev;
	spin_unlock_irqrestore(&list_lock);

	return st;
}

void handle_running_event(timer_event *event, LinkedListIterator<timer_event *> it)
{
	pending_list.Remove(event, it);

	auto callback = event->callback;
	auto context = event->context;

	if(event->can_run_in_irq)
		callback(context);
	else
	{
		panic("do something");
	}
}

extern "C"
void timer_handle_pending_events(void)
{
	spin_lock_irqsave(&list_lock);
	for(auto it = pending_list.begin();
	    it != pending_list.end(); )
	{
		auto event = *it;

		/* Not sure if we need <= but keep like that to be sure we don't miss events */
		bool needs_to_run = event->future_timestamp <= get_tick_count();

		/* Note: We increment the iterator here since handle_running_event
		 * removes the event from the list. Therefore if we did it in the for loop,
		 * it would be corrupted since the node it would point to wouldn't exist
		*/
		if(needs_to_run)
		{
			handle_running_event(event, it++);
		}
		else
			it++;
	}

	spin_unlock_irqrestore(&list_lock);
}

uint64_t timer_in_future(uint64_t offset)
{
	return get_tick_count() + offset;
}