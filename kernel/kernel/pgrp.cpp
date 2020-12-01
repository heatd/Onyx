/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/pgrp.h>
#include <onyx/hashtable.hpp>

namespace pgrp
{

static cul::hashtable2<process_group, 16, fnv_hash_t, process_group::hash> pgrp_ht;
static spinlock pgrp_ht_locks[16];

void add_to_hashtable(process_group& pgrp)
{
	auto hash = process_group::hash(pgrp);
	scoped_lock g{pgrp_ht_locks[pgrp_ht.get_hashtable_index(hash)]};

	pgrp_ht.add_element(pgrp, &pgrp.hashtable_node());
}

void remove_from_hashtable(process_group& pgrp)
{
	auto hash = process_group::hash(pgrp);
	scoped_lock g{pgrp_ht_locks[pgrp_ht.get_hashtable_index(hash)]};

	pgrp_ht.remove_element(pgrp, &pgrp.hashtable_node());
}

process_group* lookup(pid_t pid)
{
	auto hash = process_group::hash_pid(pid);
	auto index = pgrp_ht.get_hashtable_index(hash);
	scoped_lock g{pgrp_ht_locks[index]};

	auto list = pgrp_ht.get_hashtable(index);

	list_for_every(list)
	{
		auto pg = list_head_cpp<process_group>::self_from_list_head(l);

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

}

extern "C"
int sys_setpgid(pid_t pid, pid_t pgid)
{
	auto current = get_current_process();
	auto_process target_res;

	/* If pid == 0, pid = our pid; if pgid == 0, pgid = pid */

	if(!pid)
		pid = current->pid;

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

	pgrp::auto_pgrp pgrp;

	if(pgid != pid)
	{
		pgrp = pgrp::lookup(pgid);

		/* If we're moving a process from one process group to another,
		 * the process group is required to exist. */

		if(!pgrp)
			return -EPERM;
	}
	else
	{
		pgrp = pgrp::lookup(pgid);
		if(!pgrp)
		{
			/* If the process group doesn't exist yet, create it */
			if(!(pgrp = pgrp_create(target)))
			{
				return -ENOMEM;
			}
		}
	}

	auto process_group = pgrp.get();

	if(process_group != target->process_group)
	{
		auto old_pgrp = target->process_group;
		if(old_pgrp)
		{
			old_pgrp->remove_process(target);
		}

		process_group->add_process(target);

		target->process_group = process_group;

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
		pid = current->pid;
	}

	target = get_process_from_pid(pid);

	if(!target)
		return -ESRCH;

	auto proc = target.get();
	
	scoped_lock g{proc->pgrp_lock};

	auto ret = proc->process_group->get_pid();

	return ret;
}

void process_group::inherit(process *proc)
{
	scoped_lock g{proc->pgrp_lock};

	add_process(proc);
}
