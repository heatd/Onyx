/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define DEFINE_CURRENT
#include <onyx/err.h>
#include <onyx/maple_tree.h>
#include <onyx/mm/slab.h>
#include <onyx/pid.h>
#include <onyx/process.h>
#include <onyx/rculist.h>

static struct maple_tree pid_tree = MTREE_INIT(pid_tree, MT_FLAGS_USE_RCU | MT_FLAGS_ALLOC_RANGE);
static unsigned long pid_next = 1;
static struct slab_cache *pid_cache;

__init static void pid_subsys_init(void)
{
    pid_cache =
        kmem_cache_create("pid", sizeof(struct pid), _Alignof(struct pid), KMEM_CACHE_PANIC, NULL);
}

#define PID_MAX 4096

struct pid *pid_alloc(struct process *leader)
{
    unsigned long pid_id;
    int err;

    struct pid *pid = kmem_cache_alloc(pid_cache, GFP_ATOMIC);
    if (!pid)
        return ERR_PTR(-ENOMEM);

    pid->refcount = REFCOUNT_INIT(1);
    for (int i = 0; i < PIDTYPE_MAX; i++)
        INIT_LIST_HEAD(&pid->member_list[i]);
    spinlock_init(&pid->lock);
    pid->proc = leader;

    err = mtree_alloc_cyclic(&pid_tree, &pid_id, pid, 1, PID_MAX, &pid_next, GFP_KERNEL);
    if (err < 0)
    {
        kmem_cache_free(pid_cache, pid);
        return ERR_PTR(err);
    }

    CHECK(pid_id > 0);
    /* TODO: Concurrency weirdness? */
    leader->pid_struct = pid;
    pid->pid_ = pid_id;
    leader->pid_ = pid_id;
    return pid;
}

struct pid *pid_lookup(pid_t pid)
{
    struct pid *p = NULL;
    MA_STATE(mas, &pid_tree, pid, pid + 1);
    mas_lock(&mas);
    p = mas_find(&mas, pid + 1);
    mas_unlock(&mas);
    if (unlikely(!p || p->pid_ != pid))
        return NULL;
    return p;
}

struct pid *pid_lookup_ref(pid_t pid)
{
    struct pid *p = NULL;
    MA_STATE(mas, &pid_tree, pid, pid + 1);
    mas_lock(&mas);
    p = mas_find(&mas, pid + 1);
    mas_unlock(&mas);
    if (unlikely(!p || p->pid_ != pid))
        return NULL;
    if (unlikely(!refcount_inc_not_zero(&p->refcount)))
        return NULL;

    return p;
}

bool pgrp_is_in_session(struct pid *pid, struct pid *session)
{
    /* rcu read lock or appropriate locks held */
    struct process *proc;
    if (list_is_empty_rcu(&pid->member_list[PIDTYPE_PGRP]))
        return false;

    proc = list_first_entry(&pid->member_list[PIDTYPE_PGRP], struct process, pgrp_node);
    return proc->sig->session == session;
}

void pid_destroy(struct pid *pid)
{
    for (int i = 0; i < PIDTYPE_MAX; i++)
        DCHECK(list_is_empty(&pid->member_list[i]));
    kfree_rcu(pid, rcu);
}

static bool pid_empty(struct pid *pid)
{
    for (int i = 0; i < PIDTYPE_MAX; i++)
    {
        if (!list_is_empty_rcu(&pid->member_list[i]))
            return false;
    }

    return pid->proc == NULL;
}

static void free_pid(struct pid *pid)
{
    mtree_erase(&pid_tree, pid->pid_);
    put_pid(pid);
}

void pid_remove_process(struct pid *pid, struct process *proc, enum pid_type type)
{
    spin_lock(&pid->lock);

    switch (type)
    {
        case PIDTYPE_PGRP:
            list_remove_rcu(&proc->pgrp_node.__lh);
            break;
        case PIDTYPE_SID:
            list_remove_rcu(&proc->session_node.__lh);
            break;
        default:
            UNREACHABLE();
    }

    spin_unlock(&pid->lock);

    if (pid_empty(pid))
        free_pid(pid);
}

void pid_remove_pid(struct pid *pid, struct process *proc)
{
    /* Remove the PID-level association */
    spin_lock(&pid->lock);
    CHECK(proc == pid->proc);
    pid->proc = NULL;
    spin_unlock(&pid->lock);

    if (pid_empty(pid))
        free_pid(pid);
}

void pid_add_process(struct pid *pid, struct process *proc, enum pid_type type)
{
    spin_lock(&pid->lock);

    switch (type)
    {
        case PIDTYPE_PGRP:
            list_add_tail_rcu(&proc->pgrp_node.__lh, &pid->member_list[type]);
            break;
        case PIDTYPE_SID:
            list_add_tail_rcu(&proc->session_node.__lh, &pid->member_list[type]);
            break;
        default:
            UNREACHABLE();
    }

    spin_unlock(&pid->lock);
}

int sys_setpgid(pid_t pid, pid_t pgid)
{
    struct process *target, *parent;
    struct pid *pgrp, *old_pgrp;
    struct pid *session;
    int err;

    pgrp = NULL;
    /* If pid == 0, pid = our pid; if pgid == 0, pgid = pid */
    if (!pid)
        pid = task_tgid(current);

    if (!pgid)
        pgid = pid;

    if (pid < 0 || pgid < 0)
        return -EINVAL;

    write_lock(&tasklist_lock);
    target = get_process_from_pid(pid);

    /* Error out if the process doesn't exist, isn't us or isn't our child. */
    if (!target || (target != current && task_parent_locked(target) != current))
    {
        if (target)
            process_put(target);
        write_unlock(&tasklist_lock);
        return -ESRCH;
    }

    parent = task_parent_locked(target);

    /* Can't do setpgid for a child that has exec'd (the only way that flag is cleared). */
    if (parent == current && !(target->flags & PROCESS_FORKED))
    {
        err = -EACCES;
        goto err;
    }

    pgrp = pid_lookup(pgid);
    if (!pgrp)
    {
        err = -ESRCH;
        goto err;
    }

    err = -EPERM;
    session = task_session_locked(target);
    if (task_session_locked(current) != session)
        goto err;

    old_pgrp = task_pgrp_locked(target);
    if (pgrp != old_pgrp)
    {
        /* If session leader, oh no! */
        if (task_is_session_leader(target))
            goto err;

        if (pgid != pid && !pgrp_is_in_session(pgrp, session))
            goto err;

        if (old_pgrp)
            pid_remove_process(old_pgrp, target, PIDTYPE_PGRP);

        pid_add_process(pgrp, target, PIDTYPE_PGRP);
        rcu_assign_pointer(target->sig->process_group, pgrp);
    }

    write_unlock(&tasklist_lock);
    process_put(target);
    return 0;
err:
    write_unlock(&tasklist_lock);
    process_put(target);
    return err;
}

pid_t sys_getpgid(pid_t pid)
{
    struct process *target;
    if (pid < 0)
        return -EINVAL;

    /* If pid == 0, pid = us */
    if (!pid)
        pid = current->pid_;

    target = get_process_from_pid(pid);

    if (!target)
        return -ESRCH;

    rcu_read_lock();
    pid = pid_nr(task_pgrp(target));
    rcu_read_unlock();
    return pid;
}

pid_t sys_setsid(void)
{
    pid_t pid;
    struct pid *pgrp, *session;
    struct pid *tgid;
    struct process *leader;
    write_lock(&tasklist_lock);

    pgrp = task_pgrp_locked(current);
    session = task_session_locked(current);
    tgid = task_tgid_locked(current);
    leader = rcu_dereference_protected(current->sig->tg_leader, lockdep_tasklist_lock_held_write());
    if (pgrp == tgid)
    {
        // Oops, we're process group leader, can't call setsid
        write_unlock(&tasklist_lock);
        return -EPERM;
    }

    // Lets make ourselves process group leaders
    pid_remove_process(pgrp, leader, PIDTYPE_PGRP);
    rcu_assign_pointer(current->sig->process_group, tgid);
    pid_add_process(tgid, leader, PIDTYPE_PGRP);

    // and create a session on our pid
    pid_remove_process(session, leader, PIDTYPE_SID);
    rcu_assign_pointer(current->sig->session, tgid);
    pid_add_process(tgid, leader, PIDTYPE_SID);

    // Initially, we won't have a controlling terminal
    current->sig->ctty = NULL;
    pid = pid_nr(tgid);
    write_unlock(&tasklist_lock);
    return pid;
}

pid_t sys_getsid(pid_t pid)
{
    struct process *proc;
    if (!pid)
        pid = task_tgid(current);

    proc = get_process_from_pid(pid);
    if (!proc)
        return -ESRCH;

    rcu_read_lock();
    pid = pid_nr(task_session(proc));
    rcu_read_unlock();
    process_put(proc);
    return pid;
}

int pid_kill_pgrp(struct pid *pid, int sig, int flags, siginfo_t *info)
{
    int signals_sent = 0;
    struct process *proc;

    pgrp_for_every_member(pid, proc, PIDTYPE_PGRP)
    {
        if (may_kill(sig, proc, info) < 0)
            continue;
        if (kernel_raise_signal(sig, proc, 0, info) < 0)
            break;

        signals_sent++;
    }

    return signals_sent != 0 ? 0 : -EPERM;
}

bool pid_is_orphaned_and_has_stopped_jobs(struct pid *pgrp, struct process *ignore)
{
    // Definition of orphaned process group:
    // "A process group in which the parent of every member is
    // either itself a member of the group or is not a member of the group's session."

    bool has_stopped = false;
    struct process *proc, *parent;

    pgrp_for_every_member(pgrp, proc, PIDTYPE_PGRP)
    {
        if (proc == ignore)
            continue;

        if (proc->sig->signal_group_flags & SIGNAL_GROUP_STOPPED)
            has_stopped = true;

        // Ignore init, since it has no parent
        if (!proc->parent)
            continue;

        parent = task_parent_locked(proc);
        /* Not orphan */
        if (task_pgrp_locked(parent) != pgrp ||
            task_session_locked(parent) == task_session_locked(ignore))
            return false;
    }

    return has_stopped;
}

/**
 * @brief Exchange pids between us and the leader
 * Used in execve.
 *
 * @param leader Old thread group leader
 * @param new_leader New thread group leader
 */
void exchange_leader_pids(struct process *leader, struct process *new_leader)
    REQUIRES(tasklist_lock)
{
    /* tasklist_lock held in write mode */
    struct pid *pgrp = task_pgrp_locked(leader);
    struct pid *sid = task_session_locked(leader);
    struct pid *pid1 = task_pid_locked(leader);
    struct pid *pid2 = task_pid_locked(new_leader);

    list_remove_rcu(&leader->pgrp_node.__lh);
    list_remove_rcu(&leader->session_node.__lh);
    list_add_tail_rcu(&new_leader->pgrp_node.__lh, &pgrp->member_list[PIDTYPE_PGRP]);
    list_add_tail_rcu(&new_leader->session_node.__lh, &sid->member_list[PIDTYPE_SID]);
    rcu_assign_pointer(new_leader->pid_struct, pid1);
    rcu_assign_pointer(leader->pid_struct, pid2);
    leader->pid_ = pid_nr(pid2);
    new_leader->pid_ = pid_nr(pid1);
    rcu_assign_pointer(pid2->proc, leader);
    rcu_assign_pointer(pid1->proc, new_leader);
}
