/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PGRP_H
#define _ONYX_PGRP_H

#include <sys/types.h>

#include <onyx/list.h>
#include <onyx/spinlock.h>
#include <onyx/process.h>
#include <onyx/scoped_lock.h>
#include <onyx/refcount.h>
#include <onyx/fnv.h>
#include <onyx/auto_resource.h>

struct process_group;

namespace pgrp
{

void add_to_hashtable(process_group& pgrp);
void remove_from_hashtable(process_group& pgrp);

}

/* I wish we could use C++ constructs in struct process :( */
struct process_group : public refcountable
{
private:
	pid_t pid;
	mutable spinlock lock;
	list_head member_list;
	list_head_cpp<process_group> _hashtable_node;

public:
	constexpr process_group(process *leader) : pid{leader->pid}, _hashtable_node{this}
	{
		spinlock_init(&lock);
		INIT_LIST_HEAD(&member_list);
		pgrp::add_to_hashtable(*this);
	}

	~process_group()
	{
		assert(list_is_empty(&member_list));
		pgrp::remove_from_hashtable(*this);
	}

	template <typename Callable>
	void for_every_member(Callable callable) const
	{
		scoped_lock g{lock};

		list_for_every(&member_list)
		{
			auto proc = container_of(l, process, pgrp_node);

			callable(proc);
		}
	}

	/**
	 * @brief Adds a process to the process group.
	 * Note: process::pgrp_lock must be locked.
	 * 
	 * @param p Process
	 */
	void add_process(process *p)
	{
		scoped_lock g{lock};
		list_add_tail(&p->pgrp_node, &member_list);
		p->process_group = this;
		ref();
	}

	/**
	 * @brief Removes a process from the process group(usually either
	 * because it switched process groups or died). process::pgrp_lock must also be locked.
	 * 
	 * @param p Process
	 */
	void remove_process(process *p)
	{
		scoped_lock g{lock};
		list_remove(&p->pgrp_node);

		/* Unlock it before unrefing so we don't destroy the object and
		 * then call the dtor on a dead object.
		 */
		
		g.unlock();

		p->process_group = nullptr;
		unref();
	}

	void inherit(process *proc);

	list_head& hashtable_node()
	{
		return _hashtable_node;
	}

	static fnv_hash_t hash_pid(const pid_t& pid)
	{
		return fnv_hash(&pid, sizeof(pid));
	}

	static fnv_hash_t hash(process_group& grp)
	{
		return hash_pid(grp.pid);
	}

	pid_t get_pid() const
	{
		return pid;
	}
};

static inline process_group *pgrp_create(process *leader)
{
	return new process_group(leader);
}

namespace pgrp
{
	using auto_pgrp = auto_resource<process_group>;
	process_group* lookup(pid_t pid);
}

#endif
