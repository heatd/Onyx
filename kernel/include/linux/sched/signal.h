#ifndef _LINUX_SCHED_SIGNAL_H
#define _LINUX_SCHED_SIGNAL_H

#include <onyx/signal.h>
#include <linux/sched.h>

#define signal_pending(task) test_task_flag(task, TF_SIGPENDING)

#endif
