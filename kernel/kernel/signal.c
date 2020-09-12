/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <signal.h>
#include <stdio.h>
#include <errno.h>

#include <onyx/cpu.h>
#include <onyx/vm.h>
#include <onyx/signal.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/task_switching.h>
#include <onyx/wait_queue.h>
#include <onyx/clock.h>

void signal_default_term(int signum)
{
	process_exit_from_signal(signum);
}

void signal_default_core(int signum)
{
	/* TODO: Generate a core dump */
	signal_default_term(signum);
}

void signal_default_ignore(int signum)
{
	(void) signum;
}

void signal_stop_other_threads(int signum, struct process *current)
{
	spin_lock(&current->thread_list_lock);

	current->signal_group_flags |= SIGNAL_GROUP_STOP_PENDING;

	list_for_every(&current->thread_list)
	{
		struct thread *t = container_of(l, struct thread, thread_list_head);
		
		/* Let's not tkill ourselves */
		if(t == get_current_thread())
			continue;
		
		spin_unlock(&current->signal_lock);

		kernel_tkill(signum, t, 0, NULL);
	
		spin_lock(&current->signal_lock);
	}

	spin_unlock(&current->thread_list_lock);
}

void signal_do_stop(int signum)
{
	/* For every thread in the process, queue it a stop signal signal */

	struct process *current = get_current_process();

	bool first_sigstop = false;

	if(!(current->signal_group_flags & SIGNAL_GROUP_STOP_PENDING))
	{
		first_sigstop = true;
		signal_stop_other_threads(signum, current);
	}

	set_current_state(THREAD_STOPPED);

	spin_unlock(&get_current_thread()->sinfo.lock);
	spin_unlock(&current->signal_lock);

	sched_yield();

	if(first_sigstop)
	{
		current->signal_group_flags &= ~SIGNAL_GROUP_STOP_PENDING;
	}
}

/* This table only handles non-realtime signals (so, from signo 1 to 31, inclusive) */
sighandler_t dfl_signal_handlers[] = {
	[SIGHUP] = signal_default_term,
	[SIGINT] = signal_default_term,
	[SIGQUIT] = signal_default_core,
	[SIGILL] = signal_default_core,
	[SIGTRAP] = signal_default_core,
	[SIGABRT] = signal_default_core,
	[SIGBUS] = signal_default_core,
	[SIGFPE] = signal_default_core,
	[SIGKILL] = signal_default_term,
	[SIGUSR1] = signal_default_term,
	[SIGSEGV] = signal_default_core,
	[SIGUSR2] = signal_default_term,
	[SIGPIPE] = signal_default_term,
	[SIGALRM] = signal_default_term,
	[SIGTERM] = signal_default_term,
	[SIGSTKFLT] = signal_default_term,
	[SIGCHLD] = signal_default_ignore,
	[SIGCONT] = signal_default_ignore,
	[SIGURG] = signal_default_ignore,
	[SIGXCPU] = signal_default_core,
	[SIGXFSZ] = signal_default_core,
	[SIGVTALRM] = signal_default_term,
	[SIGPROF] = signal_default_term,
	[SIGWINCH] = signal_default_ignore,
	[SIGIO] = signal_default_ignore,
	[SIGPWR] = signal_default_ignore,
	[SIGSYS] = signal_default_core
};

void signal_update_pending(struct thread *thread);
void __signal_update_pending(struct thread *thread);

#define SST_SIZE (_NSIG/8/sizeof(long))
void signotset(sigset_t *set)
{
	for(size_t i = 0; i < SST_SIZE; i++)
		set->__bits[i] = ~set->__bits[i];
}

bool signal_is_unblockable(int signum)
{
	switch(signum)
	{
		case SIGSTOP:
		case SIGKILL:
			return true;
	}

	return false;
}

void do_default_signal(int signum, struct sigpending *pend)
{
	struct process *curr = get_current_process();
	struct thread *thread = get_current_thread();

	bool special_signal_handled = false;

	switch(signum)
	{
		case SIGSTOP:
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
			special_signal_handled = true;
			signal_do_stop(signum);
			break;
	}

	if(special_signal_handled)
		goto out;

	spin_unlock(&thread->sinfo.lock);
	spin_unlock(&curr->signal_lock);

	/* We need to unlock the signal table lock, because we might get killed
	 * in a moment, and having a pending lock just isn't too pretty, you know.
	 */

	/* For realtime signals(which we don't include in the dfl_signal_handlers), the default action
	 * is to terminate the process.
	 */
	if(signum < KERNEL_SIGRTMIN)
		dfl_signal_handlers[signum](signum);
	else
		signal_default_term(signum);

out:
	spin_lock(&curr->signal_lock);
	spin_lock(&thread->sinfo.lock);
}

int signal_find(struct thread *thread)
{
	sigset_t *set = &thread->sinfo.pending_set;
	sigset_t *blocked_set = &thread->sinfo.sigmask;

	for(int i = 0; i < NSIG; i++)
	{
		if(sigismember(set, i) && !sigismember(blocked_set, i))
		{
			return i;
		}
	}

	return 0;
}

bool signal_is_empty(struct thread *thread)
{
	sigset_t *set = &thread->sinfo.pending_set;
	sigset_t *blocked_set = &thread->sinfo.sigmask;
	for(int i = 0; i < NSIG; i++)
	{
		if(sigismember(set, i) && !sigismember(blocked_set, i))
			return false;
	}

	return true;
}

void __signal_add_to_blocked_set(struct thread *current, sigset_t *new)
{
	if(sigismember(new, SIGKILL))
		sigdelset(new, SIGKILL);
	if(sigismember(new, SIGSTOP))
		sigdelset(new, SIGSTOP);

	sigorset(&current->sinfo.sigmask, new, &current->sinfo.sigmask);
}

void signal_add_to_blocked_set(struct thread *current, sigset_t *new)
{
	__signal_add_to_blocked_set(current, new);
	signal_update_pending(current);
}

void signal_set_blocked_set(struct thread *current, sigset_t *new)
{
	if(sigismember(new, SIGKILL))
		sigdelset(new, SIGKILL);
	if(sigismember(new, SIGSTOP))
		sigdelset(new, SIGSTOP);
	
	memcpy(&current->sinfo.sigmask, new, sizeof(*new));
	signal_update_pending(current);
}

#define SIGNAL_QUERY_POP			(1 << 0)

struct sigpending *signal_query_pending(int signum, unsigned int flags, struct signal_info *info)
{
	list_for_every(&info->pending_head)
	{
		struct sigpending *pend = container_of(l, struct sigpending, list_node);
		
		if(pend->signum == signum)
		{
			/* Found one! */
			if(flags & SIGNAL_QUERY_POP)
				list_remove(&pend->list_node);
			return pend;
		}
	}

	return NULL;
}

void deliver_signal(int signum, struct sigpending *pending, struct registers *regs);

/* Returns negative if deliver_signal shouldn't execute the rest of the code, and should return immediately */
int force_sigsegv(struct sigpending *pending, struct registers *regs)
{
	int signum = pending->signum;

	pending->info->si_code = SI_KERNEL;
	pending->info->si_signo = SIGSEGV;
	pending->info->si_addr = NULL;

	/* If we were trying to deliver SEGV; just do the default signal */
	if(signum == SIGSEGV)
	{
		do_default_signal(signum, pending);
	}
	else
	{
		/* Else, try to deliver a SIGSEGV */
		deliver_signal(SIGSEGV, pending, regs);
		/* Explicitly return here in order not to execute the rest of the code */
		return -1;
	}

	return 0;
}

void signal_unqueue(int signum, struct thread *thread)
{
	bool is_realtime_signal = signum >= KERNEL_SIGRTMIN;
	bool should_delete = true;

	if(is_realtime_signal)
	{
		/* Search the query'ed backlog to see if there are other
		 * realtime signals(of the same signum, of course) queued.
		 */

		should_delete = signal_query_pending(signum, 0, &thread->sinfo) == NULL;
	}

	if(should_delete)
	{
		sigdelset(&thread->sinfo.pending_set, signum);
	}

	__signal_update_pending(thread);
}

void deliver_signal(int signum, struct sigpending *pending, struct registers *regs)
{
	struct thread *thread = get_current_thread();
	struct process *process = thread->owner;

	struct k_sigaction *k_sigaction = &process->sigtable[signum];
	void (*handler)(int) = k_sigaction->sa_handler;

	/* TODO: Handle SA_RESTART */
	/* TODO: Handle SA_NOCLDWAIT */
	/* TODO: Handle SA_NOCLDSTOP */

	if(handler != SIG_DFL)
	{
		if(signal_setup_context(pending, k_sigaction, regs) < 0)
		{
			if(force_sigsegv(pending, regs) < 0)
				return;
		}
	}
	else
	{
		do_default_signal(signum, pending);
	}

	if(k_sigaction->sa_flags & SA_RESETHAND)
	{
		/* If so, we need to reset the handler to SIG_DFL and clear SA_SIGINFO */
		k_sigaction->sa_handler = SIG_DFL;
		k_sigaction->sa_flags &= ~SA_SIGINFO;
	}
	
	sigset_t new_blocked;
	memcpy(&new_blocked, &k_sigaction->sa_mask, sizeof(new_blocked));

	if(!(k_sigaction->sa_flags & SA_NODEFER))
	{
		/* POSIX specifies that the signal needs to be blocked while being handled */
		sigaddset(&new_blocked, signum);
	}

	__signal_add_to_blocked_set(thread, &new_blocked);

	signal_unqueue(signum, thread);
}

void handle_signal(struct registers *regs)
{
	/* We can't do signals while in kernel space */
	if(in_kernel_space_regs(regs))
	{
		return;
	}

	context_tracking_enter_kernel();

	if(irq_is_disabled())
		irq_enable();

	struct thread *thread = get_current_thread();
	struct process *process = thread->owner;
	if(thread->flags & THREAD_SHOULD_DIE)
	{
		sched_die();
	}

	spin_lock(&process->signal_lock);

	spin_lock(&thread->sinfo.lock);

	/* Find an available signal */
	int signum = signal_find(thread);
	if(signum == 0)
	{
		spin_unlock(&thread->sinfo.lock);
		spin_unlock(&process->signal_lock);
		context_tracking_exit_kernel();
		return;
	}

	struct sigpending *pending = signal_query_pending(signum,
                                  SIGNAL_QUERY_POP, &thread->sinfo);

	assert(pending != NULL);

	deliver_signal(signum, pending, regs);

	free(pending->info);
	free(pending);

	spin_unlock(&thread->sinfo.lock);
	spin_unlock(&process->signal_lock);

	context_tracking_exit_kernel();
}

void __signal_update_pending(struct thread *thread)
{
	sigset_t *set = &thread->sinfo.pending_set;
	sigset_t *blocked_set = &thread->sinfo.sigmask;

	bool is_pending = false;

	for(int i = 0; i < NSIG; i++)
	{
		if(sigismember(set, i) && !sigismember(blocked_set, i))
		{
			is_pending = true;
			break;
		}
	}

	thread->sinfo.signal_pending = is_pending;
}

void signal_update_pending(struct thread *thread)
{
	spin_lock(&thread->sinfo.lock);

	__signal_update_pending(thread);

	spin_unlock(&thread->sinfo.lock);
}

int kernel_raise_signal(int sig, struct process *process, unsigned int flags, siginfo_t *info)
{
	struct thread *t = NULL;

	spin_lock(&process->thread_list_lock);

	list_for_every(&process->thread_list)
	{
		struct thread *thr = container_of(l, struct thread, thread_list_head);

		if(!sigismember(&thr->sinfo.sigmask, sig))
		{
			t = thr;
			break;
		}
	}

	if(t == NULL)
	{
		/* If the signal is masked everywhere, just pick the first thread... */
		t = container_of(list_first_element(&process->thread_list), struct thread,
			thread_list_head);
	}

	assert(t != NULL);

	thread_get(t);

	spin_unlock(&process->thread_list_lock);
	
	int st = kernel_tkill(sig, t, flags, info);

	thread_put(t);

	return st;
}

void do_signal_force_unblock(int signal, struct thread *thread)
{
	/* Do it like Linux, and restore the handler to SIG_DFL,
	 * and unmask the thread
	 */

	struct process *process = thread->owner;

	process->sigtable[signal].sa_handler = SIG_DFL;
	sigdelset(&thread->sinfo.sigmask, signal);
}

int may_kill(int signum, struct process *target, siginfo_t *info)
{
	bool is_kernel = !info || info->si_code > 0;
	int st = 0;

	if(is_kernel)
		return 0;

	struct creds *c = creds_get();
	struct creds *other = NULL;
	if(c->euid == 0)
		goto out;
	
	other = __creds_get(target);
	if(c->euid == other->ruid || c->euid == other->suid ||
	   c->ruid == other->ruid || c->ruid == other->suid)
		st = 0;
	else
		st = -1;

out:
	if(other)	creds_put(other);
	creds_put(c);
	return st;
}

int kernel_tkill(int signal, struct thread *thread, unsigned int flags, siginfo_t *info)
{
	struct process *process = thread->owner;

	if(may_kill(signal, process, info) < 0)
		return -EPERM;
	
	if(signal == SIGCONT && !(flags & SIGNAL_IN_BROADCAST))
	{
		assert(spin_lock_held(&process->thread_list_lock) == false);
	
		/* This requires broadcast, so broadcast it to every thread possible */
		spin_lock(&process->thread_list_lock);

		int st = 0;

		list_for_every(&process->thread_list)
		{
			struct thread *t = container_of(l, struct thread, thread_list_head);

			st = kernel_tkill(signal, t, SIGNAL_IN_BROADCAST, info);

			if(st < 0)
				break;
		}

		spin_unlock(&process->thread_list_lock);

		return st;
	}

	/* Don't bother to set it as pending if sig == SIG_IGN */
	bool is_signal_ign = (process->sigtable[signal].sa_handler == SIG_IGN) && !(signal_is_unblockable(signal));

	bool is_masked = sigismember(&thread->sinfo.sigmask, signal);

	bool signal_delivery_blocked = is_signal_ign || is_masked;

	if(flags & SIGNAL_FORCE && signal_delivery_blocked)
	{
		/* If the signal delivery is being forced for some reason
		 * (usually, it's because of a hardware exception), we'll need
		 * to unblock it forcefully.
		 */
		do_signal_force_unblock(signal, thread);
	}
	else if(is_signal_ign)
	{
		return 0;
	}

	spin_lock(&thread->sinfo.lock);

	bool standard_signal = signal < KERNEL_SIGRTMIN;

	if(standard_signal && sigismember(&thread->sinfo.pending_set, signal))
	{
		/* Already signaled, return success */
		goto success;
	}

	struct sigpending *pending = malloc(sizeof(*pending));
	if(!pending)
	{
		goto failure_oom;
	}

	siginfo_t *copy_siginfo = malloc(sizeof(siginfo_t));
	if(!copy_siginfo)
	{
		free(pending);
		goto failure_oom;
	}

	if(info)
	{
		memcpy(copy_siginfo, info, sizeof(siginfo_t));
	}
	else
	{
		memset(copy_siginfo, 0, sizeof(siginfo_t));
		copy_siginfo->si_code = SI_KERNEL;
	}

	copy_siginfo->si_signo = signal;

	pending->info = copy_siginfo;
	pending->signum = signal;

	list_add(&pending->list_node, &thread->sinfo.pending_head);

	if(signal == SIGCONT && thread->status != THREAD_STOPPED)
	{
		/* If any stop signals are pending, unqueue them */
		signal_unqueue(SIGSTOP, thread);
		signal_unqueue(SIGTSTP, thread);
		signal_unqueue(SIGTTIN, thread);
		signal_unqueue(SIGTTOU, thread);
	}

	sigaddset(&thread->sinfo.pending_set, signal);

	if(!sigismember(&thread->sinfo.sigmask, signal))
	{
		thread->sinfo.signal_pending = true;
		/* We're only waking the thread up for two reasons: It's either in an interruptible sleep
		 * OR it's stopped and we're SIGCONT'ing it */
		if(thread->status == THREAD_INTERRUPTIBLE || (process->signal_group_flags & SIGNAL_GROUP_STOP_PENDING
                                                      && signal == SIGCONT))
			thread_wake_up(thread);
	}

success:	
	spin_unlock(&thread->sinfo.lock);

	return 0;

failure_oom:

	if(flags & SIGNAL_FORCE)
	{
		/* I don't think there's another way to do this, for now */
		/* Our kernel's OOM behavior and mechanisms are iffy *at best* */
		panic("SIGNAL_FORCE couldn't be done");
	}

	spin_unlock(&thread->sinfo.lock);
	return -ENOMEM;
}

bool signal_is_masked(struct thread *thread, int sig)
{
	sigset_t *set = &thread->sinfo.sigmask;
	return (bool) sigismember(set, sig);
}

bool is_valid_signal(int sig)
{
	return sig > 0 && sig < NSIG;
}

int sys_kill(pid_t pid, int sig)
{
	int st = 0;
	struct process *p = NULL;

	if(pid > 0)
	{
		p = get_process_from_pid(pid);
		if(!p)
			return -ESRCH;	
	}
	else
		return -ENOSYS;

	/* TODO: Handle pid < 0 */
	if(sig == 0)
	{
		goto out;
	}
	
	if(!is_valid_signal(sig))
	{
		st = -EINVAL;
		goto out;
	}

	struct creds *c = creds_get();

	siginfo_t info = {};
	info.si_signo = sig;
	info.si_code = SI_USER;
	info.si_uid = c->euid;
	info.si_pid = get_current_process()->pid;

	creds_put(c);

	st = kernel_raise_signal(sig, p, 0, &info);

out:
	process_put(p);
	return st;
}

int sys_sigaction(int signum, const struct k_sigaction *act, struct k_sigaction *oldact)
{
	int st = 0;
	if(!is_valid_signal(signum))
		return -EINVAL;

	/* If both pointers are NULL, just return 0 (We can't do anything) */
	if(!oldact && !act)
		return 0;

	struct process *proc = get_current_process();

	/* Lock the signal table */
	spin_lock(&proc->signal_lock);

	/* If old_act, save the old action */
	if(oldact)
	{
		if(copy_to_user(oldact, &proc->sigtable[signum], sizeof(struct k_sigaction)) < 0)
		{
			st = -EFAULT;
			goto out;
		}
	}

	/* If act, set the new action */
	if(act)
	{
		struct k_sigaction sa;

		if(copy_from_user(&sa, act, sizeof(struct k_sigaction)) < 0)
		{
			st = -EFAULT;
			goto out;
		}

		if(act->sa_handler == SIG_ERR)
		{
			st = -EINVAL;
			goto out;
		}
		/* Check if it's actually possible to set a handler to this signal */
		switch(signum)
		{
			/* If not, return EINVAL */
			case SIGKILL:
			case SIGSTOP:
				st = -EINVAL;
				goto out;
		}

		memcpy(&proc->sigtable[signum], &sa, sizeof(sa));
	}

out:
	spin_unlock(&proc->signal_lock);

	return st;
}

int sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	struct thread *current = get_current_thread();

	if(oldset)
	{
		if(copy_to_user(oldset, &current->sinfo.sigmask, sizeof(sigset_t)) < 0)
			return -EFAULT;
	}
	
	if(set)
	{
		sigset_t kset;
		if(copy_from_user(&kset, set, sizeof(sigset_t)) < 0)
			return -EFAULT;	
		switch(how)
		{
			case SIG_BLOCK:
			{
				signal_add_to_blocked_set(current, &kset);
				break;
			}
			case SIG_UNBLOCK:
			{
				signotset(&kset);
				sigandset(&current->sinfo.sigmask, &current->sinfo.sigmask, &kset);
				signal_update_pending(current);
				break;
			}
			case SIG_SETMASK:
			{
				signal_set_blocked_set(current, &kset);
				break;
			}
			default:
				return -EINVAL;
		}
	}

	return 0;
}

bool signal_is_pending(void)
{
	struct thread *t = get_current_thread();
	if(!t)
		return false;
#if 0
	if(t->sinfo.signal_pending == true)
		printk("Signal pending!\n");
#endif

	return t->sinfo.signal_pending;
}

int sys_sigsuspend(const sigset_t *uset)
{
	struct thread *current = get_current_thread();

	sigset_t set;
	if(copy_from_user(&set, uset, sizeof(sigset_t)) < 0)
		return -EFAULT;

	/* Ok, mask the signals in set */
	sigset_t old;
	/* First, save the old sigset */
	memcpy(&old, &current->sinfo.sigmask, sizeof(sigset_t));
	/* Now, set the signal mask */
	signal_set_blocked_set(current, &set);

	/* Now, wait for a signal */	
	struct wait_queue wq;
	init_wait_queue_head(&wq);

	wait_for_event_interruptible(&wq, false);

	signal_set_blocked_set(current, &old);

	return -EINTR;
}

int sys_pause(void)
{
	struct wait_queue wq;
	init_wait_queue_head(&wq);

	wait_for_event_interruptible(&wq, false);

	return -EINTR;
}

void signal_context_init(struct thread *new_thread)
{
	INIT_LIST_HEAD(&new_thread->sinfo.pending_head);
	new_thread->sinfo.altstack.ss_flags = SS_DISABLE;
}

#define TGKILL_CHECK_PID			(1 << 0)
#define TGKILL_SIGQUEUE				(1 << 1)

int do_tgkill(int pid, int tid, int sig, unsigned int flags, siginfo_t *kinfo)
{
	int st = 0;
	if(tid < 0)
		return -EINVAL;

	struct thread *t = thread_get_from_tid(tid);
	if(!t)
	{
		return -ESRCH;
	}
	
	/* Can't send signals to kernel threads */
	if(t->flags & THREAD_KERNEL)
	{
		st = -EINVAL;
		goto out;
	}

	if(flags & TGKILL_CHECK_PID && t->owner->pid != pid)
	{
		st = -ESRCH;
		goto out;
	}

	if(!is_valid_signal(sig))
	{
		st = -EINVAL;
		goto out;
	}
	
	siginfo_t info = {};
	if(!(flags & TGKILL_SIGQUEUE))
	{
		struct creds *c = creds_get();

		info.si_signo = sig;
		info.si_code = SI_TKILL;
		info.si_uid = c->euid;
		info.si_pid = get_current_process()->pid;

		creds_put(c);
	}
	else
	{
		memcpy(&info, kinfo, sizeof(info));
	}

	st = kernel_tkill(sig, t, 0, &info);

out:
	thread_put(t);

	return st;
}

int sys_tkill(int tid, int sig)
{
	return do_tgkill(-1, tid, sig, 0, NULL);
}

int sys_tgkill(int pid, int tid, int sig)
{
	return do_tgkill(pid, tid, sig, TGKILL_CHECK_PID, NULL);
}

int sanitize_rt_sigqueueinfo(siginfo_t *info, pid_t pid)
{
	struct process *current = get_current_process();

	if(current->pid == pid)
		return 0;
	
	if(info->si_code >= 0)
		return -1;
	if(info->si_code == SI_TKILL)
		return -1;
	
	return 0;
}

int sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *uinfo)
{
	int st = 0;
	siginfo_t info;
	if(copy_from_user(&info, uinfo, sizeof(info)) < 0)
		return -EFAULT;

	if(sanitize_rt_sigqueueinfo(&info, pid) < 0)
		return -EPERM;

	struct process *p = get_process_from_pid(pid);
	if(!p)
		return -ESRCH;

	if(sig == 0)
	{
		goto out;
	}
	
	if(!is_valid_signal(sig))
	{
		st = -EINVAL;
		goto out;
	}

	st = kernel_raise_signal(sig, p, 0, &info);

out:
	process_put(p);
	return st;
}

int sys_rt_tgsigqueueinfo(pid_t pid, pid_t tid, int sig, siginfo_t *uinfo)
{
	siginfo_t info;
	if(copy_from_user(&info, uinfo, sizeof(info)) < 0)
		return -EFAULT;
	
	if(sanitize_rt_sigqueueinfo(&info, pid) < 0)
		return -EPERM;

	return do_tgkill(pid, tid, sig, TGKILL_CHECK_PID | TGKILL_SIGQUEUE, &info);
}

void signal_do_execve(struct process *proc)
{
	/* Clear the non-ignored signal disposition */
	for(int i = 0; i < NSIG; i++)
	{
		struct k_sigaction *sa = &proc->sigtable[i];
		if(sa->sa_handler != SIG_IGN)
			sa->sa_handler = NULL;
		
		sa->sa_flags = 0;
		memset(&sa->sa_mask, 0, sizeof(sa->sa_mask));
		sa->sa_restorer = NULL;
	}

	/* Clear the altstack */
	struct thread *t = get_current_thread();
	
	memset(&t->sinfo.altstack, 0, sizeof(t->sinfo.altstack));
	t->sinfo.altstack.ss_flags = SS_DISABLE;
}

#define CURRENT_SIGSETLEN				8

/* We need to separate this function since you can't have 2 wait_for_events */
/* TODO: Maybe fix it? */
long sigtimedwait_forever(struct wait_queue *wq)
{
	return wait_for_event_interruptible(wq, false);
}

int sys_rt_sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *utimeout, size_t sigsetlen)
{
	if(sigsetlen != CURRENT_SIGSETLEN)
		return -EINVAL;

	int st = 0;
	struct process *process = get_current_process();
	struct thread *thread = get_current_thread();

	struct wait_queue wq;
	init_wait_queue_head(&wq);

	struct timespec timeout = {0};

	if(utimeout && copy_from_user(&timeout, utimeout, sizeof(timeout)) < 0)
		return -EFAULT;

	if(!timespec_valid(&timeout, false))
		return -EINVAL;
	
	sigset_t kset;

	if(copy_from_user(&kset, set, sizeof(kset)) < 0)
		return -EFAULT;

	hrtime_t timeout_ns = timespec_to_hrtime(&timeout);

	long res;
	if(utimeout)
		res = wait_for_event_timeout_interruptible(&wq, false, timeout_ns);
	else
	{
		res = sigtimedwait_forever(&wq);
	}

	if(res == -ETIMEDOUT)
		return -EAGAIN;

	spin_lock(&process->signal_lock);
	spin_lock(&thread->sinfo.lock);

	/* Find a pending signal */
	int signum = signal_find(thread);
	assert(signum != 0);

	/* If it's not a member of set, error out with EINTR(it will be handled on syscall return). */
	if(!sigismember(&kset, signum))
	{
		st = -EINTR;
		goto out;
	}

	/* As in the normal signal handling path, pop the sigpending */
	struct sigpending *pending = signal_query_pending(signum,
                                  SIGNAL_QUERY_POP, &thread->sinfo);

	assert(pending != NULL);

	signal_unqueue(signum, thread);

	st = pending->signum;

	free(pending->info);
	free(pending);

	if(copy_to_user(info, pending->info, sizeof(sigset_t)) < 0)
	{
		st = -EFAULT;
		goto out;
	}

out:
	spin_unlock(&thread->sinfo.lock);
	spin_unlock(&process->signal_lock);

	return st;
}

int sys_rt_sigpending(sigset_t *uset, size_t sigsetlen)
{
	sigset_t set;
	struct thread *current = get_current_thread();

	if(sigsetlen != CURRENT_SIGSETLEN)
		return -EINVAL;

	memcpy(&set, &current->sinfo.pending_set, sizeof(set));
	sigandset(&set, &set, &current->sinfo.sigmask);

	if(copy_to_user(uset, &set, sizeof(set)) < 0)
		return -EFAULT;
	
	return 0;
}

bool executing_in_altstack(const struct syscall_frame *frm, const stack_t *stack)
{
	/* TODO: This is arch-dependent and we'd probably be better off wrapping this access
	 * with a arch-dependent macro.
	 */
	/* TODO: This depends on whether the stack grows downwards or upwards. This logic covers the first case. */
	unsigned long sp = frm->user_rsp;
	unsigned long alt_sp = (unsigned long) stack->ss_sp;
	unsigned long alt_stack_limit = alt_sp + stack->ss_size;
	return sp >= alt_sp && sp < alt_stack_limit;
}

static int alt_stack_sp_flags(const struct syscall_frame *frame, const stack_t *stack)
{
	return executing_in_altstack(frame, stack) ? SS_ONSTACK : 0;
}

#define VALID_SIGALTSTACK_FLAGS				(SS_AUTODISARM | SS_DISABLE)

int sys_sigaltstack(const stack_t *new_stack, stack_t *old_stack, const struct syscall_frame *frame)
{
	struct thread *current = get_current_thread();
	struct signal_info *sinfo = &current->sinfo;

	if(old_stack)
	{
		stack_t kold = {};
		kold.ss_sp = sinfo->altstack.ss_sp;
		kold.ss_size = sinfo->altstack.ss_size;
		kold.ss_flags = alt_stack_sp_flags(frame, &sinfo->altstack) | sinfo->altstack.ss_flags;

		if(copy_to_user(old_stack, &kold, sizeof(kold)) < 0)
			return -EFAULT;
	}

	if(new_stack)
	{
		stack_t stk;
		if(copy_from_user(&stk, new_stack, sizeof(stk)) < 0)
			return -EFAULT;
		
		if(stk.ss_flags & ~VALID_SIGALTSTACK_FLAGS)
			return -EINVAL;

		if(executing_in_altstack(frame, &sinfo->altstack))
			return -EPERM;
		
		stack_t *s = &sinfo->altstack;

		if(stk.ss_flags & SS_DISABLE)
		{
			/* We're disabling, zero out size and sp, and set the flag properly. */
			s->ss_flags = SS_DISABLE;
			s->ss_size = 0;
			s->ss_sp = NULL;
		}
		else
		{
			if(stk.ss_size < MINSIGSTKSZ)
				return -ENOMEM;

			s->ss_sp = stk.ss_sp;
			s->ss_size = stk.ss_size;
			s->ss_flags = stk.ss_flags;
		}
	}

	return 0;
}
