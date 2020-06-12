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

sleep_result poll_table::sleep_poll(hrtime_t timeout, bool timeout_valid)
{
	if(timeout == 0 && timeout_valid)
		return sleep_result::timeout;

	bool inifinite_timeout = !timeout_valid;

	set_current_state(THREAD_INTERRUPTIBLE);

	if(was_signaled())
	{
		set_current_state(THREAD_RUNNABLE);
		return sleep_result::woken_up;
	}

	if(inifinite_timeout)
		sched_yield();
	else
		sched_sleep(timeout);

	if(signaled)
		return sleep_result::woken_up;
	else if(signal_is_pending())
		return sleep_result::signal;

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

class auto_signal_mask
{
private:
	bool sigmask_valid;
	sigset_t original_sigmask;
	sigset_t& temp_sigmask;
public:
	auto_signal_mask(bool valid, sigset_t& set) : sigmask_valid{valid},
                     original_sigmask{}, temp_sigmask{set}
	{
		if(!sigmask_valid)
			return;
		auto thread = get_current_thread();
		memcpy(&original_sigmask, &thread->sinfo.sigmask, sizeof(sigset_t));
		signal_set_blocked_set(thread, &temp_sigmask);
	}

	~auto_signal_mask()
	{
		if(!sigmask_valid)
			return;
		signal_set_blocked_set(get_current_thread(), &original_sigmask);
	}
	
};

extern "C"
int sys_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *utimeout,
                     const sigset_t *usigmask, size_t sigsetsize)
{
	if(sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	bool infinite_sleep = true;
	bool valid_sigmask = false;
	sigset_t set = {};
	hrtime_t timeout = 0;

	if(utimeout)
	{
		struct timespec ts;
		if(copy_from_user(&ts, utimeout, sizeof(ts)) < 0)
			return -EFAULT;
		if(!timespec_valid(&ts, false))
			return -EINVAL;

		timeout = timespec_to_hrtime(&ts);
		infinite_sleep = false;
	}

	if(usigmask)
	{
		valid_sigmask = true;
		if(copy_from_user(&set, usigmask, sizeof(set)) < 0)
			return -EFAULT;
	}

	const auto_signal_mask mask_guard{valid_sigmask, set}; 

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

		if(!vec.push_back(cul::move(pf)))
		{
			fd_put(f);
			return -ENOMEM;
		}

		fd_put(f);
	}

	bool should_return = false;

	while(!should_return)
	{
		/* The current poll implementation wasn't safe.
		 * Particularly, we could miss wakeups in between the check and the sleep,
		 * howver I don't believe this is the case anymore.
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

		auto res = pt.sleep_poll(timeout, !infinite_sleep);
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

extern "C"
int sys_pselect(int nfds, fd_set *ureadfds, fd_set *uwritefds,
                fd_set *uexceptfds, const struct timespec *utimeout,
                struct pselect_arg *uarg)
{

	fd_set readfds, writefds, exceptfds;

	if(ureadfds)
	{
		if(copy_from_user(&readfds, ureadfds, sizeof(readfds)) < 0)
			return -EFAULT;
	}
	else
		FD_ZERO(&readfds);

	if(uwritefds)
	{
		if(copy_from_user(&writefds, uwritefds, sizeof(writefds)) < 0)
			return -EFAULT;
	}
	else
		FD_ZERO(&writefds);

	if(uexceptfds)
	{
		if(copy_from_user(&exceptfds, uexceptfds, sizeof(exceptfds)) < 0)
			return -EFAULT;
	}
	else
		FD_ZERO(&exceptfds);
	
	struct pselect_arg arg;
	if(copy_from_user(&arg, uarg, sizeof(arg)) < 0)
		return -EFAULT;

	if(arg.length != sizeof(sigset_t))
		return -EINVAL;

	if(nfds < 0)
		return -EINVAL;

	if(nfds >= FD_SETSIZE)
		return -EINVAL;

	bool infinite_sleep = true;
	bool valid_sigmask = false;
	sigset_t set = {};
	hrtime_t timeout = 0;

	if(utimeout)
	{
		struct timespec ts;
		if(copy_from_user(&ts, utimeout, sizeof(ts)) < 0)
			return -EFAULT;
		if(!timespec_valid(&ts, false))
			return -EINVAL;

		timeout = timespec_to_hrtime(&ts);
		infinite_sleep = false;
	}

	if(arg.mask)
	{
		valid_sigmask = true;
		if(copy_from_user(&set, arg.mask, sizeof(set)) < 0)
			return -EFAULT;
	}

	const auto_signal_mask mask_guard{valid_sigmask, set}; 

	int fd_bits_set = 0;

	poll_table pt;
	auto& vec = pt.get_poll_table();

	/* First, we iterate through the file descriptors and add ourselves
	 * to wait queues if they're set
	 */
	for(int i = 0; i < nfds; i++)
	{		
		short events = (FD_ISSET(i, &readfds) ? POLL_IN : 0) |
		               (FD_ISSET(i, &writefds) ? POLL_OUT : 0) |
					   (FD_ISSET(i, &exceptfds) ? POLL_PRI : 0);
		/* FD not set, continue... */
		if(!events)
			continue;

		struct file *f = get_file_description(i);
		if(!f)
		{
			return -EBADF;
		}

		poll_file pf{i, &pt, f, events, nullptr};

		if(!vec.push_back(cul::move(pf)))
		{
			fd_put(f);
			return -ENOMEM;
		}

		fd_put(f);
	}

	/* Test if they were zero'd previously - useful to save a bunch of work zeroing memory */
	if(ureadfds) FD_ZERO(&readfds);
	if(uwritefds) FD_ZERO(&writefds);
	if(uexceptfds) FD_ZERO(&exceptfds);

	bool should_return = false;

	while(!should_return)
	{
		/* The current poll implementation wasn't safe.
		 * Particularly, we could miss wakeups in between the check and the sleep,
		 * howver I don't believe this is the case anymore.
	     */

		for(auto& poll_file : vec)
		{
			auto file = poll_file.get_file();
			auto events = poll_file.get_efective_event_mask();
	
			auto revents = poll_vfs(&poll_file, events, file);

			if(revents != 0)
			{
				auto fd = poll_file.get_fd();

				if(revents & POLLIN)
				{
					FD_SET(fd, &readfds);
					fd_bits_set++;
				}

				if(revents & POLLOUT)
				{
					FD_SET(fd, &writefds);
					fd_bits_set++;
				}
			
				if(revents & POLLPRI)
				{
					FD_SET(fd, &exceptfds);
					fd_bits_set++;
				}

				should_return = true;
			}
		}

		if(should_return)
			continue;

		pt.dont_queue();

		auto res = pt.sleep_poll(timeout, !infinite_sleep);
		if(res == sleep_result::woken_up)
			continue;
		else if(res == sleep_result::timeout)
			break;
		else if(res == sleep_result::signal)
			return -EINTR;
	}

	if(ureadfds && copy_to_user(ureadfds, &readfds, sizeof(readfds)) < 0)
		return -EFAULT;
	if(uwritefds && copy_to_user(uwritefds, &writefds, sizeof(writefds)) < 0)
		return -EFAULT;
	if(uexceptfds && copy_to_user(uexceptfds, &uexceptfds, sizeof(uexceptfds)) < 0)
		return -EFAULT;

	return fd_bits_set;
}
