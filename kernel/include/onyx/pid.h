/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PGRP_H
#define _ONYX_PGRP_H

#include <stdio.h>
#include <signal.h>

#include <sys/types.h>

#include <onyx/list.h>
#include <onyx/spinlock.h>
#include <onyx/scoped_lock.h>
#include <onyx/refcount.h>
#include <onyx/fnv.h>
#include <onyx/auto_resource.h>

enum pid_type
{
	PIDTYPE_PGRP = 0,
	PIDTYPE_SID,
	PIDTYPE_MAX
};

struct process;

class pid : public refcountable
{
private:
	pid_t pid_;
	mutable spinlock lock;
	list_head member_list[PIDTYPE_MAX];
	list_head_cpp<pid> _hashtable_node;

public:
	pid(process *leader);

	~pid()
	{
		for(int i = 0; i < PIDTYPE_MAX; i++)
			assert(list_is_empty(&member_list[i]));
		remove_from_hashtable(*this);
	}

	template <typename Callable>
	void for_every_member(Callable callable, pid_type type = PIDTYPE_PGRP) const
	{
		scoped_lock g{lock};

		list_for_every(&member_list[type])
		{
			auto proc = list_head_cpp<process>::self_from_list_head(l);

			callable(proc);
		}
	}

	/**
	 * @brief Adds a process to the process group.
	 * Note: process::pgrp_lock must be locked.
	 * 
	 * @param p Process
	 * @param type Context of the usage of the pid
	 */
	void add_process(process *p, pid_type type);

	/**
	 * @brief Removes a process from the process group(usually either
	 * because it switched process groups or died). process::pgrp_lock must also be locked.
	 * 
	 * @param p Process
	 * @param type Context of the usage of the pid
	 */
	void remove_process(process *p, pid_type type);

	void inherit(process *proc, pid_type type);

	list_head& hashtable_node()
	{
		return _hashtable_node;
	}

	static fnv_hash_t hash_pid(const pid_t& pid)
	{
		return fnv_hash(&pid, sizeof(pid));
	}

	static fnv_hash_t hash(pid& grp)
	{
		return hash_pid(grp.pid_);
	}

	pid_t get_pid() const
	{
		return pid_;
	}

	static void add_to_hashtable(pid& p);
	static void remove_from_hashtable(pid& p);

	bool is_in_session(pid *session);

	using auto_pid = auto_resource<pid>;

	static auto_pid lookup(pid_t pid);

	bool is_orphaned_and_has_stopped_jobs(process *ignore) const;

	int kill_pgrp(int sig, int flags, siginfo_t *info) const;
};

static inline pid::auto_pid pid_create(process *leader)
{
	return new pid(leader);
}

#endif
