#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <onyx/process.h>

#include <linux/preempt.h>
#include <linux/bits.h>

#include <asm/processor.h>

#define task_struct process

#define MAX_SCHEDULE_TIMEOUT 0x7fffffff

#define task_is_running(task)		(READ_ONCE((task)->status) == THREAD_RUNNABLE)

#define task_tgid(task) linux_task_tgid(task)

static inline struct pid *linux_task_tgid(struct task_struct *task)
{
	return rcu_dereference(task->sig->tgid);
}

/* uhhhhhh */
#define capable(cap) (true)

/* lockdep needs to work with threads and not processes, for the time being. */
#ifdef __IS_LOCKDEP__
static inline pid_t task_pid_nr(struct task_struct *tsk)
{
	return tsk->pid_;
}
#endif

#define task_pid_vnr(task) task_pid_nr(task)

#define cond_resched() do {} while (0)

#define TASK_INTERRUPTIBLE THREAD_INTERRUPTIBLE
#define TASK_UNINTERRUPTIBLE THREAD_UNINTERRUPTIBLE
#define TASK_RUNNING THREAD_RUNNABLE

/* not optimized... */
#define __set_current_state(state) set_current_state(state)

long schedule_timeout(long timeout);

static inline int wake_up_process(struct task_struct *tsk)
{
	thread_wake_up(tsk->thr);
	return 1;
}

#endif
