/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <errno.h>

#include <onyx/cpu.h>
#include <onyx/vm.h>
#include <onyx/signal.h>
#include <onyx/panic.h>
#include <onyx/process.h>

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

void signal_cont(int signum, struct process *p)
{
	process_continue(p);
}

void signal_stop(int signum, struct process *p)
{
	process_stop(p);
}

void signal_default_cont(int signum)
{
	signal_cont(signum, get_current_process());
}

void signal_default_stop(int signum)
{
	signal_stop(signum, get_current_process());
}

sighandler_t dfl_signal_handlers[] = {
	[SIGHUP] = signal_default_term,
	[SIGINT] = signal_default_term,
	[SIGQUIT] = signal_default_core,
	[SIGILL] = signal_default_core,
	[SIGABRT] = signal_default_core,
	[SIGFPE] = signal_default_core,
	[SIGKILL] = signal_default_term,
	[SIGSEGV] = signal_default_core,
	[SIGPIPE] = signal_default_term,
	[SIGALRM] = signal_default_term,
	[SIGTERM] = signal_default_term,
	[SIGUSR1] = signal_default_term,
	[SIGUSR2] = signal_default_term,
	[SIGCHLD] = signal_default_ignore,
	[SIGCONT] = signal_default_cont,
	[SIGSTOP] = signal_default_stop,
	[SIGTSTP] = signal_default_stop,
	[SIGTTIN] = signal_default_stop,
	[SIGTTOU] = signal_default_stop
};

void signal_update_pending(struct thread *thread);

#define SST_SIZE (_NSIG/8/sizeof(long))
void signotset(sigset_t *set)
{
	for(size_t i = 0; i < SST_SIZE; i++)
		set->__bits[i] = ~set->__bits[i];
}

void sys_exit(int exitcode);

void kernel_default_signal(int signum)
{
	dfl_signal_handlers[signum](signum);
}

int signal_find(struct thread *thread)
{
	sigset_t *set = &thread->sinfo.pending_set;
	sigset_t *blocked_set = &thread->sinfo.sigmask;
	for(int i = 0; i < NSIG; i++)
	{
		if(sigismember(set, i) && !sigismember(blocked_set, i))
		{
			sigdelset(set, i);
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

void signal_setup_context(int sig, struct sigaction *sigaction, struct registers *regs);

void handle_signal(struct registers *regs)
{
	/* We can't do signals while in kernel space */
	if(in_kernel_space_regs(regs))
	{
		return;
	}

	struct thread *current_thread = get_current_thread();
	if(current_thread->flags & THREAD_SHOULD_DIE)
		sched_die();

	/* Find an available signal */
	int signum = signal_find(current_thread);
	if(signum == 0)
		return;

	sigdelset(&current_thread->sinfo.pending_set, signum);
	signal_update_pending(current_thread);

	struct process *current = get_current_process();
	
	struct sigaction *sigaction = &current->sigtable[signum];
	void (*handler)(int) = sigaction->sa_handler;

	/* TODO: Handle SA_RESTART */
	/* TODO: Handle SA_NODEFER */
	/* TODO: Handle SA_NOCLDWAIT */
	/* TODO: Handle SA_ONSTACK */
	/* TODO: Handle SA_NOCLDSTOP */

	if(handler != SIG_DFL)
	{
		signal_setup_context(signum, sigaction, regs);
	}
	else
	{
		kernel_default_signal(signum);
	}

	if(sigaction->sa_flags & SA_RESETHAND)
	{
		/* If so, we need to reset the handler to SIG_DFL and clear SA_SIGINFO */
		sigaction->sa_handler = SIG_DFL;
		sigaction->sa_flags &= ~SA_SIGINFO;
	}
}

void signal_update_pending(struct thread *thread)
{
	sigset_t *set = &thread->sinfo.pending_set;
	sigset_t *blocked_set = &thread->sinfo.sigmask;
	for(int i = 0; i < NSIG; i++)
	{
		if(sigismember(set, i) && !sigismember(blocked_set, i))
		{
			thread->sinfo.signal_pending = true;
			return;
		}
	}

	thread->sinfo.signal_pending = false;
}

void kernel_raise_signal(int sig, struct process *process)
{
	/* BIG TODO: the thread list doesn't have a lock protecting it,
	 * making this inherently unsafe. Fix.
	*/

	struct thread *t = NULL;

	for(size_t i = 0; i < process->nr_threads; i++)
	{
		struct thread *thr = process->threads[i];
		if(!sigismember(&thr->sinfo.sigmask, sig))
		{
			t = thr;
			break;
		}
	}

	if(t == NULL)
	{
		/* If the signal is masked everywhere, just pick the first thread... */
		t = process->threads[0];
	}

	assert(t != NULL);

	kernel_tkill(sig, t);
}

int kernel_tkill(int signal, struct thread *thread)
{
	struct process *process = thread->owner;
	/* Don't bother to set it as pending if sig == SIG_IGN */
	if(process->sigtable[signal].sa_handler == SIG_IGN)
		return 0;

	sigaddset(&thread->sinfo.pending_set, signal);
	if(!sigismember(&thread->sinfo.sigmask, signal))
		thread->sinfo.signal_pending = true;

	return 0;
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
	struct process *p = NULL;
	struct process *current = get_current_process();
	if(pid > 0)
	{
		if(pid == current->pid)
			p = current;
		else
		{
			p = get_process_from_pid(pid);
			if(!p)
				return -ESRCH;	
		}

	}
	else
		return -1;

	/* TODO: Handle pid < 0*/

	if(sig == 0)
		return 0;
	
	if(!is_valid_signal(sig))
		return -EINVAL;

	kernel_raise_signal(sig, p);

	return 0;
}

int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	if(!is_valid_signal(signum))
		return -EINVAL;

	/* If both pointers are NULL, just return 0 (We can't do anything) */
	if(!oldact && !act)
		return 0;
	struct process *proc = get_current_process();

	/* Lock the mutex */
	mutex_lock(&proc->signal_lock);

	/* If old_act, save the old action */
	if(oldact)
	{
		if(copy_to_user(oldact, &proc->sigtable[signum], sizeof(struct sigaction)) < 0)
			return -EFAULT;
	}

	/* If act, set the new action */
	if(act)
	{
		if(act->sa_handler == SIG_ERR)
		{
			mutex_unlock(&proc->signal_lock);
			return -EINVAL;
		}
		/* Check if it's actually possible to set a handler to this signal */
		switch(signum)
		{
			/* If not, return EINVAL */
			case SIGKILL:
			case SIGSTOP:
				mutex_unlock(&proc->signal_lock);
				return -EINVAL;
		}
	
		if(copy_from_user(&proc->sigtable[signum], act, sizeof(struct sigaction)) < 0)
			return -EFAULT;
	}

	mutex_unlock(&proc->signal_lock);
	return 0;
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
				sigorset(&current->sinfo.sigmask, &current->sinfo.sigmask, &kset);
				if(sigismember(&current->sinfo.sigmask, SIGKILL))
					sigdelset(&current->sinfo.sigmask, SIGKILL);
				if(sigismember(&current->sinfo.sigmask, SIGSTOP))
					sigdelset(&current->sinfo.sigmask, SIGSTOP);
				break;
			}
			case SIG_UNBLOCK:
			{
				signotset(&kset);
				sigandset(&current->sinfo.sigmask, &current->sinfo.sigmask, &kset); 
				break;
			}
			case SIG_SETMASK:
			{
				memcpy(&current->sinfo.sigmask, &kset, sizeof(sigset_t));
				break;
			}
			default:
				return -EINVAL;
		}
	}

	signal_update_pending(current);
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
	memcpy(&current->sinfo.sigmask, &set, sizeof(sigset_t));

	/* Now, wait for a signal */
	while(!signal_is_pending())
		sched_yield();
	memcpy(&current->sinfo.sigmask, &old, sizeof(sigset_t));

	return -EINTR;
}

int sys_pause(void)
{
	while(!signal_is_pending())
		sched_yield();
	return -EINTR;
}

int sys_tkill(int tid, int sig)
{
	if(tid < 0)
		return -EINVAL;

	struct thread *t = thread_get_from_tid(tid);
	if(!t)
		return -ESRCH;
	
	/* Can't send signals to kernel threads */
	if(t->flags & THREAD_KERNEL)
		return -EINVAL;

	if(!is_valid_signal(sig))
		return -EINVAL;
	
	return kernel_tkill(sig, t);
}
