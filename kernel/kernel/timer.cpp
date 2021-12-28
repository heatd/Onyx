/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <string.h>
#include <errno.h>

#include <onyx/timer.h>
#include <onyx/spinlock.h>
#include <onyx/panic.h>
#include <onyx/softirq.h>
#include <onyx/user.h>
#include <onyx/vm.h>
#include <onyx/process.h>
#include <onyx/scoped_lock.h>

#include <sys/time.h>

void timer_queue_clockevent(struct clockevent *ev)
{
	auto timer = platform_get_timer();

	scoped_lock<spinlock, true> g2{ev->lock};
	scoped_lock<spinlock, true> g{timer->event_list_lock};

	if(ev->flags & CLOCKEVENT_FLAG_POISON)
		panic("Tried to queue clockevent that's already queued");

	ev->timer = timer;

	list_add_tail(&ev->list_node, &timer->event_list);

	ev->flags |= CLOCKEVENT_FLAG_POISON;

	if(timer->next_event > ev->deadline)
	{
		timer->next_event = ev->deadline;
		timer->set_oneshot(ev->deadline);
	}
}

void timer_disable(struct timer *t)
{
	if(t->disable_timer)
		t->disable_timer();
}

void timer_handle_events(struct timer *t)
{
	bool atomic_context = irq_is_disabled();
	bool has_raised_softirq = false;

	auto current_time = clocksource_get_time();

	unsigned long cpu_flags = spin_lock_irqsave(&t->event_list_lock);

	hrtime_t lowest = UINT64_MAX;

	list_for_every_safe(&t->event_list)
	{
		struct clockevent *ev = container_of(l, struct clockevent, list_node);
		if(ev->deadline > current_time)
		{
			lowest = lowest < ev->deadline ? lowest : ev->deadline;
			continue;
		}

		if(!atomic_context || ev->flags & CLOCKEVENT_FLAG_ATOMIC)
		{
			ev->callback(ev);
			if(!(ev->flags & CLOCKEVENT_FLAG_PULSE))
			{
				ev->flags &= ~CLOCKEVENT_FLAG_POISON;
				list_remove(&ev->list_node);
				ev->timer = nullptr;
			}
			else
			{
				lowest = lowest < ev->deadline ? lowest : ev->deadline;
			}
		}
		else
		{
			ev->flags |= CLOCKEVENT_FLAG_PENDING;
			if(!has_raised_softirq)
			{
				has_raised_softirq = true;
				softirq_raise(SOFTIRQ_VECTOR_TIMER);
			}
		}
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

	spin_unlock_irqrestore(&t->event_list_lock, cpu_flags);
}

void timer_cancel_event(struct clockevent *ev)
{
	scoped_lock<spinlock, true> g{ev->lock};
	auto timer = ev->timer;

	/* ev->timer is set after list_remove up there, therefore we check first
	 * if ev->timer is nullptr. If so, it's not in there and we don't need to lock.
	 * If it's set, we lock the event list, and recheck for CLOCKEVENT_POISON; if it's set,
	 * the event is still in there and we need to list_remove it.
	 */
	if(timer != nullptr)
	{
		unsigned long cpu_flags = spin_lock_irqsave(&timer->event_list_lock);

		if(ev->flags & CLOCKEVENT_FLAG_POISON)
		{
			list_remove(&ev->list_node);
			ev->flags &= ~CLOCKEVENT_FLAG_POISON;
		}

		spin_unlock_irqrestore(&timer->event_list_lock, cpu_flags);
	}
}

void itimer_init(struct process *p)
{
	int timer_whichs[3] = {ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF};
	int i = 0;

	for(auto &it : p->timers)
	{
		it.p = p;
		it.which = timer_whichs[i++];
		it.ev = {};
		it.armed = false;
		it.lock = {};
		it.interval_delta = 0;
	}
}

static bool valid_itimer_which(int which)
{
	/* TODO: Add other timers */
	if(which != ITIMER_REAL)
		return false;

	return true;
}

int sys_getitimer(int which, struct itimerval *curr_value)
{
	if(!valid_itimer_which(which))
		return -EINVAL;
	
	itimerval v{};

	struct process *current = get_current_process();

	auto &timer = current->timers[which];
	
	scoped_lock guard{timer.lock};

	if(timer.armed)
	{
		hrtime_to_timeval(timer.interval_delta, &v.it_interval);

		hrtime_delta_t delta = timer.ev.deadline - clocksource_get_time();

		/* Clamp the delta to 1 if it's negative or 0, since it may be
		 * undefined or just mislead the caller into thinking the timer isn't armed.
		 */

		if(delta <= 0)
			delta = 1;
	
		hrtime_to_timeval(delta, &v.it_value);
	}

	if(copy_to_user(curr_value, &v, sizeof(v)) < 0)
		return -EFAULT;

	return 0;
}

int itimer_which_to_signal(itimer *t)
{
	switch(t->which)
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

	if(armed)
	{
		timer_cancel_event(&ev);
	}

	interval_delta = interval;
	ev.callback = itimer_callback;
	ev.priv = this;
	ev.flags = (interval_delta ? CLOCKEVENT_FLAG_PULSE : 0);
	ev.timer = nullptr;
	ev.deadline = clocksource_get_time() + initial;

	timer_queue_clockevent(&ev);

	armed = true;

	return 0;
}

int itimer::disarm()
{
	scoped_lock g{lock};

	if(armed)
		timer_cancel_event(&ev);
	return 0;
}

int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value)
{
	if(!valid_itimer_which(which))
		return -EINVAL;

	int st = 0;
	
	itimerval v{};
	if(copy_from_user(&v, new_value, sizeof(v)) < 0)
		return -EFAULT;
	
	if(old_value)
	{
		/* For now, calling the syscall directly works okay */
		st = sys_getitimer(which, old_value);
		if(st < 0)
			return st;
	}

	hrtime_t interval_ns, initial_ns;

	if(!timeval_valid(&v.it_interval, false) || !timeval_valid(&v.it_value, false))
		return -EINVAL;

	interval_ns = timeval_to_hrtime(&v.it_interval);
	initial_ns = timeval_to_hrtime(&v.it_value);

	struct process *current = get_current_process();

	auto &timer = current->timers[which];

	if(!initial_ns)
		st = timer.disarm();
	else
		st = timer.arm(interval_ns, initial_ns);

	return st;
}
