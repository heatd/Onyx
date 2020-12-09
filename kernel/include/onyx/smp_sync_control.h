/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_SMP_SYNC_CONTROL_H
#define _ONYX_SMP_SYNC_CONTROL_H

#include <onyx/tuple.hpp>
#include <onyx/wait_queue.h>
#include <onyx/atomic.hpp>
#include <onyx/smp.h>

namespace smp
{

namespace internal
{

struct sync_call_cntrlblk
{
	sync_call_func f;
	void *ctx;
	atomic<unsigned long> waiting_for_completion;

	sync_call_cntrlblk(sync_call_func f, void *ctx) : f{f}, ctx{ctx}, waiting_for_completion{}
	{
	}

	void wait(sync_call_func local, void *context2);

	void complete();
};

struct sync_call_elem
{
	sync_call_cntrlblk& control_block;
	struct list_head node;

	constexpr sync_call_elem(sync_call_cntrlblk& b) : control_block{b}, node{} {}
};

}

}

#endif
