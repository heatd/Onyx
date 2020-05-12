/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>

#include <onyx/poll.h>
#include <onyx/vfs.h>
#include <onyx/file.h>
#include <onyx/signal.h>

void poll_file_entry::wake_callback(void *context, struct wait_queue_token *tkn)
{
	poll_file *e = static_cast<poll_file *>(context);
	e->signal();
}

void poll_file_entry::wait_on()
{
	wait_token.thread = get_current_thread();
	wait_token.context = f;
	wait_token.callback = wake_callback;
	wait_queue_add(queue, &wait_token);
}

void poll_file_entry::stop_wait_on()
{
	/* If wait_token.thread is filled, we know it has been queued, so unqueue */
	if(wait_token.thread != nullptr)
		wait_queue_remove(queue, &wait_token);
}

void poll_file::wait(wait_queue *queue)
{
	if(!pt->may_queue())
		return;

	/* TODO: Maybe panic'ing on these situations is a bad idea? */
	auto f = make_unique<poll_file_entry>(this, queue);

	assert(f != nullptr);

	assert(entries.push_back(cul::move(f)) != false);

	auto& file = entries.back();
	file->wait_on();
}

sleep_result poll_table::sleep_poll(int timeout)
{
	if(timeout == 0)
		return sleep_result::timeout;

	bool inifinite_timeout = timeout < 0;

	set_current_state(THREAD_INTERRUPTIBLE);

	if(was_signaled())
	{
		set_current_state(THREAD_RUNNABLE);
		return sleep_result::woken_up;
	}

	if(inifinite_timeout)
		sched_yield();
	else
		sched_sleep_ms(static_cast<unsigned long>(timeout));
	
	if(signal_is_pending())
		return sleep_result::signal;
	else if(signaled)
		return sleep_result::woken_up;

	return sleep_result::timeout;
}

void poll_file::signal()
{
	pt->signal();
}

constexpr short default_poll_return = (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM);

extern "C"
short default_poll(void *pf, short events, struct file *f)
{
	return default_poll_return & events;
}

extern "C"
int sys_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	int nr_nonzero_revents = 0;

	poll_table pt;
	struct pollfd *end = fds + nfds;
	auto& vec = pt.get_poll_table();

	/* First, we iterate through the file descriptors and add ourselves to wait queues */
	for(struct pollfd *it = fds; it != end; it++)
	{
		struct pollfd kpollfd;
		if(copy_from_user(&kpollfd, it, sizeof(struct pollfd)) < 0)
			return -EFAULT;

		/* poll(3) specifies that negative file descriptors should be ignored */
		if(kpollfd.fd < 0)
		{
			/* poll(3) specifies that we should zero out revents in these cases */
			kpollfd.revents = 0;
			if(copy_to_user(it, &kpollfd, sizeof(struct pollfd)) < 0)
				return -EFAULT;
			continue;
		}

		struct file *f = get_file_description(kpollfd.fd);
		if(!f)
		{
			kpollfd.revents = POLLNVAL;
			nr_nonzero_revents++;
			if(copy_to_user(it, &kpollfd, sizeof(struct pollfd)) < 0)
				return -EFAULT;
			continue;
		}

		poll_file pf{kpollfd.fd, &pt, f, kpollfd.events, it};

		vec.push_back(cul::move(pf));

		fd_put(f);
	}

	bool should_return = false;

	while(!should_return)
	{
		/* TODO: The current poll implementation isn't safe.
		 * Particularly, we can miss wakeups in between the check and the sleep
		 */

		for(auto& poll_file : vec)
		{
			auto file = poll_file.get_file();
			auto events = poll_file.get_efective_event_mask();

			auto revents = poll_vfs(&poll_file, events, file);

			if(revents != 0)
			{
				struct pollfd pfd;
				pfd.fd = poll_file.get_fd();
				pfd.events = poll_file.get_event_mask();
				pfd.revents = revents;

				auto upollfd = poll_file.get_upollfd();
				/* Flush the structure to userspace */
				if(copy_to_user(upollfd, &pfd, sizeof(struct pollfd)) < 0)
					return -EFAULT;

				nr_nonzero_revents++;
				should_return = true;
			}
		}

		if(should_return)
			continue;

		pt.dont_queue();

		auto res = pt.sleep_poll(timeout);
		if(res == sleep_result::woken_up)
			continue;
		else if(res == sleep_result::timeout)
			break;
		else if(res == sleep_result::signal)
			return -EINTR;
	}

	return nr_nonzero_revents;
}

extern "C"
void poll_wait_helper(void *__poll_file, struct wait_queue *q)
{
	poll_file *pf = static_cast<poll_file *>(__poll_file);
	pf->wait(q);
}
