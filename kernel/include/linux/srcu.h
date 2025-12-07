#ifndef _LINUX_SRCU_H
#define _LINUX_SRCU_H

#include <linux/mutex.h>
#include <linux/lockdep.h>

struct srcu_struct
{
    struct mutex lock;
    unsigned int completed;
    /* TODO: percpu counters... */
    unsigned long ongoing[2];
};

#if 0
#ifdef CONFIG_LOCKDEP
#error "todo"
#define init_srcu_struct(srcu) \
({ \
	static struct lock_class_key __srcu_key; \
    __init_srcu_struct(&(srcu), &__srcu_key); \
})
#else
int init_srcu_struct(struct srcu_struct *srcu);
#endif
#endif

int srcu_read_lock(struct srcu_struct *srcu);
void srcu_read_unlock(struct srcu_struct *srcu, int idx);

void synchronize_srcu(struct srcu_struct *srcu);

#define DEFINE_STATIC_SRCU(name)          \
static struct srcu_struct name = {        \
    .lock = MUTEX_INITIALIZER(name.lock), \
}

#endif
