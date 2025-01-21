/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _ONYX_PGRP_H
#define _ONYX_PGRP_H

#include <stdio.h>

#include <onyx/fnv.h>
#include <onyx/list.h>
#include <onyx/rculist.h>
#include <onyx/rcupdate.h>
#include <onyx/ref.h>
#include <onyx/spinlock.h>
#include <onyx/types.h>

#include <uapi/signal.h>

#ifdef __cplusplus
#include <onyx/scoped_lock.h>
#endif

enum pid_type
{
    PIDTYPE_PGRP = 0,
    PIDTYPE_SID,
    PIDTYPE_MAX
};

struct process;

struct pid
{
    refcount_t refcount;
    pid_t pid_;
    struct spinlock lock;
    struct process *proc;
    struct list_head member_list[PIDTYPE_MAX];
    struct rcu_head rcu;

#ifdef __cplusplus
    template <typename Callable>
    void for_every_member(Callable callable, pid_type type = PIDTYPE_PGRP)
    {
        scoped_lock g{lock};

        list_for_every (&member_list[type])
        {
            auto proc = list_head_cpp<process>::self_from_list_head(l);

            callable(proc);
        }
    }
#endif

/* XXX: Kind of a PITA to generically iterate because of session_node vs pgrp_node... */
#define pgrp_for_every_member(pid, pos, pid_type) \
    list_for_each_entry (pos, &(pid)->member_list[pid_type], pgrp_node.__lh)
};

__BEGIN_CDECLS

struct pid *pid_alloc(struct process *leader);
bool pgrp_is_in_session(struct pid *pid, struct pid *session);

void pid_destroy(struct pid *pid);

void _Z11stack_tracev(void);

static inline void get_pid(struct pid *pid)
{
    refcount_inc(&pid->refcount);
}

static inline bool get_pid_not_zero(struct pid *pid)
{
    return refcount_inc_not_zero(&pid->refcount);
}

static inline void put_pid(struct pid *pid)
{
    if (refcount_dec_and_test(&pid->refcount))
        pid_destroy(pid);
}

int pid_kill_pgrp(struct pid *pid, int sig, int flags, siginfo_t *info);
bool pid_is_orphaned_and_has_stopped_jobs(struct pid *pgrp, struct process *ignore);

void pid_remove_process(struct pid *pid, struct process *proc, enum pid_type type);
void pid_add_process(struct pid *pid, struct process *proc, enum pid_type type);

struct pid *pid_lookup(pid_t pid);
struct pid *pid_lookup_ref(pid_t pid);

static inline bool pid_is(struct pid *pid, enum pid_type type)
{
    return !list_is_empty_rcu(&pid->member_list[type]);
}

static inline pid_t pid_nr(struct pid *pid)
{
    return pid->pid_;
}

__END_CDECLS

#endif
