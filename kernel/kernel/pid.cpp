/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#include <onyx/pid.h>
#include <onyx/process.h>

#include <onyx/hashtable.hpp>

static cul::hashtable2<pid, 16, fnv_hash_t, pid::hash> pid_ht;
static spinlock pid_ht_locks[16];

void pid::add_to_hashtable(pid &p)
{
    auto hash = pid::hash(p);
    scoped_lock g{pid_ht_locks[pid_ht.get_hashtable_index(hash)]};

    pid_ht.add_element(p, &p.hashtable_node());
}

void pid::remove_from_hashtable(pid &p)
{
    auto hash = pid::hash(p);
    scoped_lock g{pid_ht_locks[pid_ht.get_hashtable_index(hash)]};

    pid_ht.remove_element(p, &p.hashtable_node());
}

pid::auto_pid pid::lookup(pid_t pid)
{
    auto hash = pid::hash_pid(pid);
    auto index = pid_ht.get_hashtable_index(hash);
    scoped_lock g{pid_ht_locks[index]};

    auto list = pid_ht.get_hashtable(index);

    list_for_every (list)
    {
        auto pg = list_head_cpp<struct pid>::self_from_list_head(l);

        /* If we're looking at a ghostly process group
         * that's about to get destroyed, ignore it. BOO!
         */
        if (pg->get_pid() == pid && !pg->is_ghost_object())
        {
            pg->ref();
            return pg;
        }
    }

    return nullptr;
}

int sys_setpgid(pid_t pid, pid_t pgid)
{
    auto current = get_current_process();
    auto_process target_res;

    /* If pid == 0, pid = our pid; if pgid == 0, pgid = pid */

    if (!pid)
        pid = current->get_pid();

    if (!pgid)
        pgid = pid;

    if (pid < 0 || pgid < 0)
        return -EINVAL;

    target_res = get_process_from_pid(pid);
    auto target = target_res.get();

    /* Error out if the process doesn't exist, isn't us or isn't our child. */
    if (!target_res || (target != current && target->parent != current))
    {
        return -ESRCH;
    }

    /* Can't do setpgid for a child that has exec'd(the only way that flag is cleared). */
    if (target->parent == current && !(target->flags & PROCESS_FORKED))
    {
        return -EACCES;
    }

    scoped_lock g{target->pgrp_lock};

    pid::auto_pid pgrp;

    pgrp = pid::lookup(pgid);
    if (!pgrp)
    {
        return -ESRCH;
    }

    if (target->session != current->session)
        return -EPERM;

    if (pgrp != target->process_group)
    {
        if (target->is_session_leader_unlocked())
            return -EPERM;

        if (pgid != pid && !pgrp->is_in_session(target->session))
            return -EPERM;

        auto old_pgrp = target->process_group;
        if (old_pgrp)
        {
            old_pgrp->remove_process(target, PIDTYPE_PGRP);
        }

        pgrp->add_process(target, PIDTYPE_PGRP);

        target->process_group = pgrp;
    }

    return 0;
}

pid_t sys_getpgid(pid_t pid)
{
    if (pid < 0)
        return -EINVAL;

    auto current = get_current_process();
    auto_process target;

    /* If pid == 0, pid = us */
    if (!pid)
    {
        pid = current->get_pid();
    }

    target = get_process_from_pid(pid);

    if (!target)
        return -ESRCH;

    auto proc = target.get();

    scoped_lock g{proc->pgrp_lock};

    auto ret = proc->process_group->get_pid();

    return ret;
}

void pid::inherit(process *proc, pid_type type)
{
    scoped_lock g{proc->pgrp_lock};

    add_process(proc, type);
}

void pid::remove_process(process *p, pid_type type)
{
    scoped_lock g{lock};

    if (type == PIDTYPE_PGRP)
    {
        list_remove(&p->pgrp_node);
        p->process_group = nullptr;
    }
    else if (type == PIDTYPE_SID)
    {
        list_remove(&p->session_node);
        p->session = nullptr;
    }
    /* Unlock it before unrefing so we don't destroy the object and
     * then call the dtor on a dead object.
     */

    g.unlock();

    unref();
}

void pid::add_process(process *p, pid_type type)
{
    scoped_lock g{lock};

    if (type == PIDTYPE_PGRP)
    {
        list_add_tail(&p->pgrp_node, &member_list[type]);
        p->process_group = this;
    }
    else if (type == PIDTYPE_SID)
    {
        list_add_tail(&p->session_node, &member_list[type]);
        p->session = this;
    }

    ref();
}

pid::pid(process *leader) : pid_{leader->get_pid()}, _hashtable_node{this}
{
    spinlock_init(&lock);

    for (int i = 0; i < PIDTYPE_MAX; i++)
        INIT_LIST_HEAD(&member_list[i]);
    add_to_hashtable(*this);
}

pid_t sys_setsid()
{
    auto current = get_current_process();

    if (current->process_group == current->pid_struct)
    {
        // Oops, we're process group leader, can't call setsid
        return -EPERM;
    }

    scoped_lock g{current->pgrp_lock};

    // TODO: These look like good candidates for separate functions
    // Lets make ourselves process group leaders
    current->process_group->remove_process(current, PIDTYPE_PGRP);
    current->process_group = current->pid_struct;
    current->process_group->add_process(current, PIDTYPE_PGRP);

    // and create a session on our pid
    current->session->remove_process(current, PIDTYPE_SID);
    current->session = current->pid_struct;
    current->session->add_process(current, PIDTYPE_SID);

    // Initially, we won't have a controlling terminal
    current->ctty = nullptr;

    return current->session->get_pid();
}

pid_t sys_getsid(pid_t pid)
{
    if (!pid)
        pid = get_current_process()->get_pid();

    auto_process proc = get_process_from_pid(pid);
    if (!proc)
        return -ESRCH;

    scoped_lock g{proc->pgrp_lock};
    return proc->session->get_pid();
}

bool pid::is_in_session(pid *session)
{
    scoped_lock g{lock};
    if (list_is_empty(&member_list[PIDTYPE_PGRP]))
        return false;

    auto head = list_first_element(&member_list[PIDTYPE_PGRP]);
    auto proc = list_head_cpp<process>::self_from_list_head(head);

    return proc->session.get() == session;
}

int pid::kill_pgrp(int sig, int flags, siginfo_t *info) const
{
    int signals_sent = 0;
    for_every_member([&](process *proc) {
        if (may_kill(sig, proc, info) < 0)
            return;
        if (kernel_raise_signal(sig, proc, 0, info) < 0)
            return;

        signals_sent++;
    });

    return signals_sent != 0 ? 0 : -EPERM;
}

bool pid::is_orphaned_and_has_stopped_jobs(process *ignore) const
{
    // Definition of orphaned process group:
    // "A process group in which the parent of every member is
    // either itself a member of the group or is not a member of the group's session."

    bool has_stopped = false;
    bool is_orphaned = true;

    // TODO: Our for_every_member can't break early
    for_every_member(
        [&](process *p) {
            if (p == ignore)
                return;

            if (p->signal_group_flags & SIGNAL_GROUP_STOPPED)
                has_stopped = true;

            // Ignore init, since it has no parent
            if (!p->parent)
                return;

            if (p->parent->process_group != this || p->parent->session == ignore->session)
                is_orphaned = false;
        },
        PIDTYPE_PGRP);

    return has_stopped && is_orphaned;
}
