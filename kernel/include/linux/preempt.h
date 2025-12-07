#ifndef _LINUX_PREEMPT_H
#define _LINUX_PREEMPT_H

#include <onyx/preempt.h>
#include <onyx/irq.h>

#define HARDIRQ_SHIFT 0
#define SOFTIRQ_SHIFT 0

/* XXX we don't maintain hardirq count */
#define hardirq_count() (irq_is_disabled() ? 1 : 0)
#define softirq_count() (sched_get_preempt_counter())
#define in_interrupt() (is_in_interrupt())

#define in_atomic() (irqs_disabled() || sched_get_preempt_counter())

#endif
