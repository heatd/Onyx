/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VIRTIO_UTILS_HPP_
#define _VIRTIO_UTILS_HPP_

#include <onyx/wait_queue.h>

template <typename T>
class virtio_control_msg
{
private:
	T *data;
	wait_queue response_waitqueue;
public:
	virtio_control_msg(T *data) : data{data}
	{
		init_wait_queue_head(&response_waitqueue);
	}

	~virtio_control_msg() {}

	void wait_for_response();
};

#endif
