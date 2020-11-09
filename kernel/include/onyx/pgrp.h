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

struct process_group
{
private:
	pid_t pid;
	mutable spinlock lock;
	list_head member_list;

public:
	constexpr process_group(pid_t pid) : pid{pid}
	{
		spinlock_init(&lock);
		INIT_LIST_HEAD(&member_list);
	}

	template <typename Callable>
	void for_every_member(Callable callable) const
	{
		scoped_lock g{lock};

		list_for_every(&member_list)
		{
			auto process = list_head_cpp<process>::self_from_list_head(l);

			callable(process);
		}
	}
};

#endif
