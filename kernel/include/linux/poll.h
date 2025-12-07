#ifndef _LINUX_POLL_H
#define _LINUX_POLL_H

#include <onyx/poll.h>
#include <linux/types.h>
#include <linux/ktime.h>

#define EPOLLIN 0x001
#define EPOLLPRI 0x002
#define EPOLLOUT 0x004
#define EPOLLRDNORM 0x040
#define EPOLLRDBAND 0x080
#define EPOLLWRNORM 0x100
#define EPOLLWRBAND 0x200
#define EPOLLMSG 0x400
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLRDHUP 0x2000

struct poll_table_struct;

static inline void poll_wait(struct file *filp, struct wait_queue *head,
                             struct poll_table_struct *table)
{
    poll_wait_helper(table, head);
}

#endif
