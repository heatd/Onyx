/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VIRTIO_UTILS_HPP_
#define _VIRTIO_UTILS_HPP_

#include <onyx/wait_queue.h>
#include <onyx/list.h>
#include <onyx/memory.hpp>
#include <onyx/tuple.hpp>
#include <onyx/pair.hpp>
#include <onyx/scoped_lock.h>

#include "virtio.hpp"

namespace virtio
{

template <typename SentType, typename ReceivedType>
class virtio_control_msg;

template <typename SentType, typename ReceivedType>
class virtio_control_msg_queue
{
private:
	struct list_head control_msgs;
	int vq_nr;
	spinlock list_lock;
	vdev *dev;
public:
	virtio_control_msg_queue(vdev *dev, int vq_nr) : control_msgs{}, vq_nr{vq_nr}, list_lock{}, dev{dev}
	{
		INIT_LIST_HEAD(&control_msgs);
	}

	~virtio_control_msg_queue(){}

	void append_msg(virtio_control_msg<SentType, ReceivedType> *msg)
	{
		scoped_lock<spinlock, true> g{&list_lock};

		list_add_tail(&msg->list_node, &control_msgs);
	}

	void remove_msg(virtio_control_msg<SentType, ReceivedType> *msg)
	{
		scoped_lock<spinlock, true> g{&list_lock};

		list_remove(&msg->list_node);
	}

	const unique_ptr<virtq>& get_vq()
	{
		return dev->get_vq(vq_nr);
	}

	void handle_used_buf(const virtq_used_elem& elem);
};

template <typename SentType, typename ReceivedType>
class virtio_control_msg
{
private:
	cul::slice<SentType> out;
	cul::slice<ReceivedType> in;
	virtio_control_msg_queue<SentType, ReceivedType>& queue;
	bool response_received;
	wait_queue response_waitqueue;
	virtio_buf_list l;
public:
	list_head_cpp<virtio_control_msg> list_node;

	virtio_control_msg(cul::slice<SentType> &out, cul::slice<ReceivedType> &in,
	                   virtio_control_msg_queue<SentType, ReceivedType>& q)
	        : out{out}, in{in}, queue{q}, response_received{false}, response_waitqueue{},
			l{queue.get_vq()}, list_node{this}
	{
		init_wait_queue_head(&response_waitqueue);
	}

	bool send()
	{
		auto &vq = l.vq;
		if(!l.prepare(out.data(), out.size_bytes(), false))
			return false;

		if(!l.prepare(in.data(), in.size_bytes(), true))
			return false;

		if(!vq->allocate_descriptors(l))
			return false;

		queue.append_msg(this);

		return vq->put_buffer(l);
	}

	~virtio_control_msg() {}

	int wait_for_response()
	{
		/* Do we need timeouts? I'm guessing probably not since if
		 * you can't trust the host to respond in time you probably can't trust it at all.
		 */
		wait_for_event(&response_waitqueue, response_received);
		return 0;
	}

	void signal()
	{
		response_received = true;
		wait_queue_wake_all(&response_waitqueue);
	}

	bool is_this_msg(const virtq_used_elem& elem)
	{
		auto lh = container_of(list_first_element(&l.buf_list_head), virtio_buf, buf_list_memb);
		return elem.id == lh->index;
	}
};

template <typename SentType, typename ReceivedType>
void virtio_control_msg_queue<SentType, ReceivedType>::handle_used_buf(const virtq_used_elem& elem)
{
	scoped_lock<spinlock, true> g{&list_lock};

	list_for_every_safe(&control_msgs)
	{
		auto m = list_head_cpp<virtio_control_msg<SentType, ReceivedType>>::self_from_list_head(l);
		if(m->is_this_msg(elem))
		{
			m->signal();
		}
	}
}

}

#endif
