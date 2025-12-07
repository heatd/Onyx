#ifndef _LINUX_KTHREAD_H
#define _LINUX_KTHREAD_H

#include <linux/types.h>

#include <linux/compiler_attributes.h>
#include <linux/sched.h>

struct kthread_worker {
	struct task_struct *task;
};

struct kthread_work;

typedef void (*kthread_work_func_t)(struct kthread_work *work);
struct kthread_work {
    kthread_work_func_t work_fn;
};

void kthread_flush_worker(struct kthread_worker *kw);
void kthread_destroy_worker(struct kthread_worker *kw);

bool kthread_queue_work(struct kthread_worker *kw, struct kthread_work *work);
bool kthread_cancel_work_sync(struct kthread_work *work);
void kthread_flush_work(struct kthread_work *work);

static inline void kthread_init_work(struct kthread_work *work, kthread_work_func_t work_fn)
{
    work->work_fn = work_fn;
}

#define sched_set_fifo(thr) do {} while (0)

__printf(2, 3)
struct kthread_worker *kthread_create_worker(unsigned int flags, const char *namefmt, ...);

#define kthread_run_worker(flags, namefmt, ...)					\
({										\
	struct kthread_worker *__kw						\
		= kthread_create_worker(flags, namefmt, ## __VA_ARGS__);	\
	if (!IS_ERR(__kw))							\
		wake_up_process(__kw->task);					\
	__kw;									\
})

#endif
