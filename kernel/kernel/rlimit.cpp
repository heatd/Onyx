/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/process.h>
#include <onyx/thread.h>

#include <sys/resource.h>

int process::rlimit(int rsrc, struct rlimit *old, const struct rlimit *new_lim, unsigned int flags)
{
	scoped_rwlock<rw_lock::write> g{rlimit_lock};

	auto &lim = rlimits[rsrc];

	if(old)
	{
		old->rlim_cur = lim.rlim_cur;
		old->rlim_max = lim.rlim_max;
	}

	if(!new_lim)
		return 0;

	bool is_root = is_root_user();

	if(!is_root)
	{
		/* Non-root gets some extra checks:
		 * 1) Is the new soft limit <= the hard limit?
		 * 2) Is the new hard limit the same as the old hard limit?(non-root can't set hard limits.)
		 */

		if(new_lim->rlim_max != lim.rlim_max)
			return -EPERM;

		if(new_lim->rlim_cur > lim.rlim_max)
			return -EPERM;
	}

	lim.rlim_cur = new_lim->rlim_cur;
	lim.rlim_max = new_lim->rlim_max;

	/* **** Extra special resource limit handling goes here **** */
	return 0;
}

struct rlimit process::get_rlimit(int rsrc)
{
	scoped_rwlock<rw_lock::read> g{rlimit_lock};

	return rlimits[rsrc];
}

void process::init_default_limits()
{
	for(auto &l : rlimits)
	{
		l.rlim_cur = RLIM_INFINITY;
		l.rlim_max = RLIM_INFINITY;
	}
}

constexpr int nlimits = 16;

void process::inherit_limits(process *parent)
{
	for(int i = 0; i < nlimits; i++)
	{
		rlimits[i] = parent->rlimits[i];
	}
}

#define VALID_RLIMIT_FLAGS 0

/* prlimit(2) inspired, but with more sanity and better naming */
extern "C" int sys_rlimit(pid_t pid, int resource, rlimit *uold, const rlimit *unew_lim,
                          unsigned int flags)
{
	if(flags & ~VALID_RLIMIT_FLAGS)
		return -EINVAL;
	
	if(resource < 0 || resource >= nlimits)
		return -EINVAL;

	if(!pid)
		pid = get_current_process()->pid;

	auto_process ap = get_process_from_pid(pid);

	if(!ap)
		return -ESRCH;

	auto p = ap.get();

	rlimit old, new_lim;

	if(unew_lim)
	{
		if(copy_from_user(&new_lim, unew_lim, sizeof(rlimit)) < 0)
			return -EFAULT;
	}

	int st = p->rlimit(resource, uold ? &old : nullptr, unew_lim ? &new_lim : nullptr, flags);

	if(st == 0)
	{
		if(uold)
		{
			if(copy_to_user(uold, &old, sizeof(rlimit)) < 0)
				return -EFAULT;
		}
	}

	return st;
}
