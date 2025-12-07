#ifndef _LINUX_WORKQUEUE_H
#define _LINUX_WORKQUEUE_H

#include <linux/timer.h>

struct workqueue_struct;

struct work_struct
{
};

struct delayed_work
{
    struct work_struct work;
};

extern struct workqueue_struct *system_long_wq;

void schedule_work(struct work_struct *work);
bool queue_work(struct workqueue_struct *wq, struct work_struct *work);
#define INIT_WORK_ONSTACK(work, workfn) do {} while (0)
#define INIT_WORK(work, workfn) do {} while (0)

bool flush_work(struct work_struct *work);

static inline void destroy_work_on_stack(struct work_struct *work)
{
}

void destroy_workqueue(struct workqueue_struct *wq);

#endif
