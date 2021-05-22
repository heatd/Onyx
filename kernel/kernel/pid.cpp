/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/pid.h>
#include <onyx/hashtable.hpp>
#include <onyx/process.h>

static cul::hashtable2<pid, 16, fnv_hash_t, pid::hash> pid_ht;
static spinlock pid_ht_locks[16];

void pid::add_to_hashtable(pid& p)
{
	auto hash = pid::hash(p);
	scoped_lock g{pid_ht_locks[pid_ht.get_hashtable_index(hash)]};

	pid_ht.add_element(p, &p.hashtable_node());
}

void pid::remove_from_hashtable(pid& p)
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

	list_for_every(list)
	{
		auto pg = list_head_cpp<class pid>::self_from_list_head(l);

		/* If we're looking at a ghostly process group
		 * that's about to get destroyed, ignore it. BOO!
		 */
		if(pg->get_pid() == pid && !pg->is_ghost_object())
		{
			pg->ref();
			return pg;
		}
	}

	return nullptr;
}

extern "C"
int sys_setpgid(pid_t pid, pid_t pgid)
{
	auto current = get_current_process();
	auto_process target_res;

	/* If pid == 0, pid = our pid; if pgid == 0, pgid = pid */

	if(!pid)
		pid = current->get_pid();

	if(!pgid)
		pgid = pid;
	
	if(pid < 0 || pgid < 0)
		return -EINVAL;

	target_res = get_process_from_pid(pid);
	auto target = target_res.get();

	/* Error out if the process doesn't exist, isn't us or isn't our child. */
	if(!target_res || (target != current && target->parent != current))
	{
		return -ESRCH;
	}

	/* Can't do setpgid for a child that has exec'd(the only way that flag is cleared). */
	if(target->parent == current && !(target->flags & PROCESS_FORKED))
	{
		return -EACCES;
	}

	/* TODO: Deal with sessions when we add them. */

	scoped_lock g{target->pgrp_lock};

	pid::auto_pid pgrp_;

	if(pgid != pid)
	{
		pgrp_ = pid::lookup(pgid);

		/* If we're moving a process from one process group to another,
		 * the process group is required to exist. */

		if(!pgrp_)
			return -EPERM;
	}
	else
	{
		pgrp_ = pid::lookup(pgid);
		if(!pgrp_)
		{
			return -ESRCH;
		}
	}

	auto pgrp = pgrp_.get();

	if(pgrp != target->process_group)
	{
		auto old_pgrp = target->process_group;
		if(old_pgrp)
		{
			old_pgrp->remove_process(target);
		}

		pgrp->add_process(target);

		target->process_group = pgrp;

		assert(target->process_group != nullptr);
	}

	return 0;
}

extern "C"
pid_t sys_getpgid(pid_t pid)
{
	auto current = get_current_process();
	auto_process target;

	/* If pid == 0, pid = us */
	if(!pid)
	{
		pid = current->get_pid();
	}

	target = get_process_from_pid(pid);

	if(!target)
		return -ESRCH;

	auto proc = target.get();
	
	scoped_lock g{proc->pgrp_lock};

	auto ret = proc->process_group->get_pid();

	return ret;
}

void pid::inherit(process *proc)
{
	scoped_lock g{proc->pgrp_lock};

	add_process(proc);
}

void pid::remove_process(process *p, pid_type type)
{
	scoped_lock g{lock};

	if(type == PIDTYPE_PGRP)
	{
		list_remove(&p->pgrp_node);
		p->process_group = nullptr;
	}
	else if(type == PIDTYPE_SID)
	{
		// TODO
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

	if(type == PIDTYPE_PGRP)
	{
		list_add_tail(&p->pgrp_node, &member_list[type]);
		p->process_group = this;
	}
	else if(type == PIDTYPE_SID)
	{
		// TODO
	}

	ref();
}

pid::pid(process *leader) : pid_{leader->get_pid()}, _hashtable_node{this}
{
	spinlock_init(&lock);
	
	for(int i = 0; i < PIDTYPE_MAX; i++)
		INIT_LIST_HEAD(&member_list[i]);
	add_to_hashtable(*this);
}
