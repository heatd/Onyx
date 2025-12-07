#ifndef _LINUX_COMPLETION_H
#define _LINUX_COMPLETION_H

#include <linux/wait.h>

struct completion {
	unsigned int done;
    struct wait_queue wait;
};

unsigned long wait_for_completion_timeout(struct completion *comp, unsigned long timeout);

static inline void init_completion(struct completion *c)
{
	c->done = 0;
	init_wait_queue_head(&c->wait);
}

void complete_all(struct completion *comp);

#endif
