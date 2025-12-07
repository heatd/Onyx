#ifndef _LINUX_WAIT_H
#define _LINUX_WAIT_H

#include <onyx/wait_queue.h>
#include <linux/poll.h>

#define wait_queue_head wait_queue

typedef struct wait_queue wait_queue_head_t;
#define init_waitqueue_head(head) init_wait_queue_head(head)

/* TODO: timeout return is not being correctly emulated now. */
#define wait_event_timeout(wq, cond, timeout) wait_for_event_timeout(&(wq), cond, (timeout) * NS_PER_MS)
#define wait_event_interruptible_timeout(wq, cond, timeout) wait_for_event_timeout_interruptible(&(wq), cond, (timeout) * NS_PER_MS)
#define wait_event_interruptible(wq, cond) wait_for_event_interruptible(&(wq), cond)
#define wait_event_lock_irq(wq, cond, lock)                                          \
__wait_for_event(&(wq), cond, THREAD_UNINTERRUPTIBLE, spin_unlock_irq(&(lock)); sched_yield(); \
                     spin_lock_irq(&(lock)))

#define poll_to_key(m) ((void *)(__force uintptr_t)(__poll_t)(m))
#define wake_up_interruptible_poll(wq_head, key) ((__wait_queue_wake(wq_head, 0, poll_to_key(key), 1)))
#define wake_up(wq) ((__wait_queue_wake(wq, 0, NULL, 1)))
#define wake_up_all(wq) ((__wait_queue_wake(wq, 0, NULL, -1)))
#endif
