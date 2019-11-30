/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/poll.h>

void poll_file::wait_on()
{
	wait_token.thread = get_current_thread();
	wait_queue_add(queue, &wait_token);
}

void poll_file::stop_wait_on()
{
	/* If wait_token.thread is filled, we know it has been queued, so unqueue */
	if(wait_token.thread != nullptr)
		wait_queue_remove(queue, &wait_token);
}

void poll_table::wait(struct inode *ino, short events, wait_queue *queue)
{
	if(!is_queueing)
		return;

	object_ref(&ino->i_object);

	spin_lock(&poll_table_lock);

	poll_table_array.push_back(poll_file{ino, events});

	auto& file = poll_table_array.back();

	file.set_wait_queue(queue);
	file.wait_on();

	spin_unlock(&poll_table_lock);
}