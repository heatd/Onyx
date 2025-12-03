#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <onyx/process.h>

#define task_struct process

#define MAX_SCHEDULE_TIMEOUT 0xffffffff

#define task_is_running(task)		(READ_ONCE((task)->status) == THREAD_RUNNABLE)

#endif
