/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/irqflags.h
 *
 * IRQ flags tracing: follow the state of the hardirq and softirq flags and
 * provide callbacks for transitions between ON and OFF states.
 *
 * This file gets included from lowlevel asm headers too, to provide
 * wrapped versions of the local_irq_*() APIs, based on the
 * raw_local_irq_*() macros from the lowlevel headers.
 */
#ifndef _LINUX_TRACE_IRQFLAGS_LOCKDEP_H
#define _LINUX_TRACE_IRQFLAGS_LOCKDEP_H

#include <linux/irqflags_types.h>
#include <asm/percpu.h>

struct thread;

/* Currently lockdep_softirqs_on/off is used only by lockdep */
#ifdef CONFIG_PROVE_LOCKING
  extern void lockdep_softirqs_on(unsigned long ip);
  extern void lockdep_softirqs_off(unsigned long ip);
  extern void lockdep_hardirqs_on_prepare(void);
  extern void lockdep_hardirqs_on(unsigned long ip);
  extern void lockdep_hardirqs_off(unsigned long ip);
  extern void lockdep_cleanup_dead_cpu(unsigned int cpu,
				       struct thread *idle);
#else
  static inline void lockdep_softirqs_on(unsigned long ip) { }
  static inline void lockdep_softirqs_off(unsigned long ip) { }
  static inline void lockdep_hardirqs_on_prepare(void) { }
  static inline void lockdep_hardirqs_on(unsigned long ip) { }
  static inline void lockdep_hardirqs_off(unsigned long ip) { }
  static inline void lockdep_cleanup_dead_cpu(unsigned int cpu,
					      struct thread *idle) {}
#endif

#ifdef CONFIG_TRACE_IRQFLAGS

DECLARE_PER_CPU(int, hardirqs_enabled);
DECLARE_PER_CPU(int, hardirq_context);

extern void trace_hardirqs_on_prepare(void);
extern void trace_hardirqs_off_finish(void);
extern void trace_hardirqs_on(void);
extern void trace_hardirqs_off(void);

# define lockdep_hardirq_context()	(raw_cpu_read(hardirq_context))
# define lockdep_softirq_context(p)	((p)->softirq_context)
# define lockdep_hardirqs_enabled()	(this_cpu_read(hardirqs_enabled))
# define lockdep_softirqs_enabled(p)	((p)->softirqs_enabled)
# define lockdep_hardirq_enter()			\
do {							\
	if (__this_cpu_inc_return(hardirq_context) == 1)\
		current->hardirq_threaded = 0;		\
} while (0)
# define lockdep_hardirq_threaded()		\
do {						\
	current->hardirq_threaded = 1;		\
} while (0)
# define lockdep_hardirq_exit()			\
do {						\
	__this_cpu_dec(hardirq_context);	\
} while (0)

# define lockdep_hrtimer_enter(__hrtimer)		\
({							\
	bool __expires_hardirq = true;			\
							\
	if (!__hrtimer->is_hard) {			\
		current->irq_config = 1;		\
		__expires_hardirq = false;		\
	}						\
	__expires_hardirq;				\
})

# define lockdep_hrtimer_exit(__expires_hardirq)	\
	do {						\
		if (!__expires_hardirq)			\
			current->irq_config = 0;	\
	} while (0)

# define lockdep_posixtimer_enter()				\
	  do {							\
		  current->irq_config = 1;			\
	  } while (0)

# define lockdep_posixtimer_exit()				\
	  do {							\
		  current->irq_config = 0;			\
	  } while (0)

# define lockdep_irq_work_enter(_flags)					\
	  do {								\
		  if (!((_flags) & IRQ_WORK_HARD_IRQ))			\
			current->irq_config = 1;			\
	  } while (0)
# define lockdep_irq_work_exit(_flags)					\
	  do {								\
		  if (!((_flags) & IRQ_WORK_HARD_IRQ))			\
			current->irq_config = 0;			\
	  } while (0)

#else
# define trace_hardirqs_on_prepare()		do { } while (0)
# define trace_hardirqs_off_finish()		do { } while (0)
# define trace_hardirqs_on()			do { } while (0)
# define trace_hardirqs_off()			do { } while (0)
# define lockdep_hardirq_context()		0
# define lockdep_softirq_context(p)		0
# define lockdep_hardirqs_enabled()		0
# define lockdep_softirqs_enabled(p)		0
# define lockdep_hardirq_enter()		do { } while (0)
# define lockdep_hardirq_threaded()		do { } while (0)
# define lockdep_hardirq_exit()			do { } while (0)
# define lockdep_softirq_enter()		do { } while (0)
# define lockdep_softirq_exit()			do { } while (0)
# define lockdep_hrtimer_enter(__hrtimer)	false
# define lockdep_hrtimer_exit(__context)	do { (void)(__context); } while (0)
# define lockdep_posixtimer_enter()		do { } while (0)
# define lockdep_posixtimer_exit()		do { } while (0)
# define lockdep_irq_work_enter(__work)		do { } while (0)
# define lockdep_irq_work_exit(__work)		do { } while (0)
#endif

#if defined(CONFIG_TRACE_IRQFLAGS) && !defined(CONFIG_PREEMPT_RT)
# define lockdep_softirq_enter()		\
do {						\
	current->softirq_context++;		\
} while (0)
# define lockdep_softirq_exit()			\
do {						\
	current->softirq_context--;		\
} while (0)

#else
# define lockdep_softirq_enter()		do { } while (0)
# define lockdep_softirq_exit()			do { } while (0)
#endif
#endif
