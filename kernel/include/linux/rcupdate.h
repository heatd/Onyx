#ifndef _LINUX_RCUPDATE_H
#define _LINUX_RCUPDATE_H

#include <onyx/rcupdate.h>

static inline void init_rcu_head(struct rcu_head *head) { }
static inline void destroy_rcu_head(struct rcu_head *head) { }
static inline void init_rcu_head_on_stack(struct rcu_head *head) { }
static inline void destroy_rcu_head_on_stack(struct rcu_head *head) { }

#define synchronize_rcu_expedited() synchronize_rcu()

#endif
