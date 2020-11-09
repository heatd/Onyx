/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <sys/resource.h>

#include <onyx/user.h>
#include <onyx/id.h>
#include <onyx/vdso.h>
#include <onyx/compiler.h>
#include <onyx/elf.h>
#include <onyx/process.h>
#include <onyx/task_switching.h>
#include <onyx/cpu.h>
#include <onyx/random.h>
#include <onyx/mutex.h>
#include <onyx/panic.h>
#include <onyx/binfmt.h>
#include <onyx/worker.h>
#include <onyx/page.h>
#include <onyx/thread.h>
#include <onyx/file.h>
#include <onyx/slab.h>
#include <onyx/proc_event.h>
#include <onyx/syscall.h>
#include <onyx/futex.h>
#include <onyx/utils.h>
#include <onyx/scoped_lock.h>

#include <pthread_kernel.h>

#define __WCONSTRUCT(nature, exitcode, signal) \
        (((nature) & 0xFF) << 16 | \
         ((exitcode) & 0xFF) << 8 | \
         ((signal) & 0x7F) << 0)

extern PML *current_pml4;
ids *process_ids = nullptr;

process *first_process = nullptr;
static struct process *process_tail = nullptr;
static spinlock process_list_lock;
slab_cache_t *process_cache = nullptr;

void process_destroy(thread_t *);
void process_end(struct process *process);

void process_append_children(process *parent, process *children)
{
	scoped_lock g{parent->children_lock};

	process **pp = &parent->children;

	while(*pp)
		pp = &(*pp)->next_sibbling;
	
	*pp = children;

	children->prev_sibbling = container_of(pp, process, next_sibbling);
}

void process_append_to_global_list(process *p)
{
	scoped_lock g{process_list_lock};
	
	if(process_tail)
	{
		process_tail->next = p;
		process_tail = p;
	}
	else
	{
		first_process = process_tail = p;
	}

	p->next = nullptr;
}

process::process()
{
	/* FIXME: DANGEROUS, BUT WORKS */
	memset((void *) this, 0, sizeof(process));
}

process *process_create(const char *cmd_line, ioctx *ctx, process *parent)
{
	if(unlikely(!process_ids))
	{
		process_ids = idm_add("pid", 1, UINTMAX_MAX);
		assert(process_ids != nullptr);
	}

	auto proc = new process;
	if(!proc)
		return errno = ENOMEM, nullptr;
	
	/* TODO: idm_get_id doesn't wrap? POSIX COMPLIANCE */
	mutex_init(&proc->condvar_mutex);
	mutex_init(&proc->ctx.fdlock);
	proc->refcount = 1;
	proc->pid = idm_get_id(process_ids);
	assert(proc->pid != (pid_t) -1);
	proc->cmd_line = strdup(cmd_line);
	creds_init(&proc->cred);

	itimer_init(proc);

	if(!proc->cmd_line)
	{
		free(proc);
		return nullptr;
	}

	if(ctx)
	{
		fd_get(ctx->cwd);

		proc->ctx.cwd = ctx->cwd;
		
		if(copy_file_descriptors(proc, ctx) < 0)
		{
			fd_put(ctx->cwd);
			free(proc->cmd_line);
			free(proc);
			return nullptr;
		}
	}
	else
	{
		if(allocate_file_descriptor_table(proc) < 0)
		{
			free(proc);
			return nullptr;
		}

		proc->ctx.umask = S_IWOTH | S_IWGRP;
	}

	if(parent)
	{
		/* Inherit the parent process' properties */
		proc->personality = parent->personality;
		proc->vdso = parent->vdso;
		process_inherit_creds(proc, parent);
		proc->address_space.brk = parent->address_space.brk;
		/* Inherit the signal handlers of the process and the
		 * signal mask of the current thread
		*/

		{
		scoped_lock g{proc->signal_lock};
		memcpy(&proc->sigtable, &parent->sigtable, sizeof(k_sigaction) * _NSIG);
		}

		/* Note that the signal mask is inherited at thread creation */
		
		/* Note that pending signals are zero'd, as per POSIX */

		process_append_children(parent, proc);

		proc->parent = parent;
	}

	proc->address_space.process = proc;

	process_append_to_global_list(proc);

	INIT_LIST_HEAD(&proc->thread_list);

	return proc;
}

process *get_process_from_pid(pid_t pid)
{
	/* TODO: Maybe storing processes in a tree would be a good idea? */
	scoped_lock g{process_list_lock};

	for(process *p = first_process; p != nullptr; p = p->next)
	{
		if(p->pid == pid)
		{
			process_get(p);
			return p;
		}
	}

	return nullptr;
}

void unlock_process_list(void)
{
	spin_unlock(&process_list_lock);
}

extern "C" pid_t sys_getppid()
{
	if(get_current_process()->parent)
		return get_current_process()->parent->pid;
	else
		return -1;
}

bool process_found_children(pid_t pid, struct process *proc)
{
	scoped_lock g{proc->children_lock};

	if(proc->children)
	{
		/* if we have children, return true */
		return true;
	}

	for(process *p = proc->children; p != nullptr; p = p->next_sibbling)
	{
		if(p->pid == pid)
		{
			return true;
		}
	}

	return false;
}

void process_remove_from_list(struct process *process);

bool wait4_find_dead_process(struct process *proc, pid_t pid, int *wstatus,
                             rusage *user_usage, pid_t *ret)
{
	bool looking_for_any = pid < 0;
	rusage r = {0};

	for(process *p = proc->children; p != nullptr; p = p->next_sibbling)
	{
		if((p->pid == pid || looking_for_any) && p->has_exited)
		{
			if(wstatus)
			{
				errno = EFAULT;
				if(copy_to_user(wstatus, &p->exit_code, sizeof(int)) < 0)
					return false;
			}

			*ret = p->pid;

			hrtime_to_timeval(p->system_time, &r.ru_utime);
			hrtime_to_timeval(p->user_time, &r.ru_utime);

			if(user_usage && copy_to_user(user_usage, &r, sizeof(r)) < 0)
				return false;

			__atomic_add_fetch(&proc->children_utime, p->user_time / NS_PER_MS, __ATOMIC_RELAXED);
			__atomic_add_fetch(&proc->children_stime, p->system_time / NS_PER_MS, __ATOMIC_RELAXED);

			spin_unlock(&proc->children_lock);

			process_put(p);

			return true;
		}
	}

	return false;
}

extern "C" pid_t sys_wait4(pid_t pid, int *wstatus, int options, rusage *usage)
{
	process *current = get_current_process();

	if(!process_found_children(pid, current))
	{
		return -ECHILD;
	}

	while(true)
	{
		if(signal_is_pending())
		{
			return -EINTR;
		}

		scoped_lock g{current->children_lock};

		pid_t ret;
		errno = 0;

		if(wait4_find_dead_process(current, pid, wstatus, usage, &ret))
		{
			// Was already unlocked by wait4_find_dead_process
			g.keep_locked();
			return ret;
		}
		else
		{
			if(errno == EFAULT)
			{
				return -EFAULT;
			}
		}

		g.unlock();

		sem_wait(&current->wait_sem);
	}

	return 0;
}

void process_copy_current_sigmask(thread *dest)
{
	memcpy(&dest->sinfo.sigmask, &get_current_thread()->sinfo.sigmask, sizeof(sigset_t));
}

extern "C" pid_t sys_fork(syscall_frame *ctx)
{
	process *proc;
	process *child;
	thread_t *to_be_forked;

	proc = (process*) get_current_process();
	to_be_forked = get_current_thread();	
	/* Create a new process */
	child = process_create(strdup(proc->cmd_line), &proc->ctx, proc);

	if(!child)
		return -ENOMEM;
	
	child->address_space.process = child;

	/* Fork the vmm data and the address space */
	if(vm_fork_address_space(&child->address_space) < 0)
		return -ENOMEM;

	/* Fork and create the new thread */
	thread *new_thread = process_fork_thread(to_be_forked, child, ctx);

	if(!new_thread)
	{
		panic("TODO: Add process destruction here.\n");
	}

	process_copy_current_sigmask(new_thread);

	sched_start_thread(new_thread);

	// Return the pid to the caller
	return child->pid;
}

int make_wait4_wstatus(int signum, bool core_dumped, int exit_code)
{
	int wstatus = 0;

	wstatus = ((int) core_dumped << 7);

	if(signum == 0)
	{
		wstatus |= ((exit_code & 0xff) << 8);
		return wstatus;
	}
	else
	{
		switch(signum)
		{
			case SIGCONT:
			case SIGSTOP:
				wstatus |= (0177 << 0);
				break;
			default:
				wstatus |= (signum << 0); 
		}

		wstatus |= (signum << 8);

		return wstatus;

	}
}

void process_exit_from_signal(int signum)
{
	process *current = get_current_process();
	if(current->pid == 1)
	{
		printk("Panic: %s exited with signal %d!\n",
			get_current_process()->cmd_line, signum);
		ENABLE_INTERRUPTS();
		for(;;);
	}

	current->has_exited = 1;
	current->exit_code = make_wait4_wstatus(signum, false, 0);

	thread_t *current_thread = get_current_thread();

	process_destroy(current_thread);
}

extern "C" void sys_exit(int status)
{
	status &= 0xff;
	process *current = get_current_process();
	if(current->pid == 1)
	{
		printk("Panic: %s returned!\n", get_current_process()->cmd_line);
		ENABLE_INTERRUPTS();
		for(;;);
	}

	current->has_exited = 1;
	current->exit_code = make_wait4_wstatus(0, false, status);

	/* TODO: Support multi-threaded processes */
	thread_t *current_thread = get_current_thread();

	process_destroy(current_thread);
}

extern "C" uint64_t sys_getpid(void)
{
	return get_current_process()->pid;
}

extern "C" int sys_personality(unsigned long val)
{
	// TODO: Use this syscall for something. This might be potentially very useful
	get_current_process()->personality = val;
	return 0;
}

void process_destroy_aspace(void)
{
	process *current = get_current_process();

	vm_destroy_addr_space(&current->address_space);
}

void process_destroy_file_descriptors(struct process *process)
{
	ioctx *ctx = &process->ctx;
	file **table = ctx->file_desc;
	mutex_lock(&ctx->fdlock);

	for(unsigned int i = 0; i < ctx->file_desc_entries; i++)
	{
		if(!table[i])
			continue;

		fd_put(table[i]);
	}

	free(table);

	ctx->file_desc = nullptr;
	ctx->file_desc_entries = 0;

	mutex_unlock(&ctx->fdlock);
}

void process_remove_from_list(struct process *proc)
{
	{
	scoped_lock g{process_list_lock};
	/* TODO: Make the list a doubly-linked one, so we're able to tear it down more easily */
	if(first_process == proc)
	{
		first_process = first_process->next;
		if(process_tail == proc)
			process_tail = first_process;
	}
	else
	{
		process *p;
		for(p = first_process; p->next != proc && p->next; p = p->next);
		
		assert(p->next != nullptr);

		p->next = proc->next;

		if(process_tail == proc)
			process_tail = p;
	}

	}

	/* Remove from the sibblings list */

	scoped_lock g{proc->parent->children_lock};

	if(proc->prev_sibbling)
		proc->prev_sibbling->next_sibbling = proc->next_sibbling;
	else
		proc->parent->children = proc->next_sibbling;

	if(proc->next_sibbling)
		proc->next_sibbling->prev_sibbling = proc->prev_sibbling;
}

void process_wait_for_dead_threads(struct process *process)
{
	while(process->nr_threads)
	{
		cpu_relax();
	}
}

void process_end(struct process *process)
{
	process_remove_from_list(process);

	process_wait_for_dead_threads(process);

	free(process->cmd_line);
	process->cmd_line = nullptr;
	
	if(process->ctx.cwd)
		fd_put(process->ctx.cwd);

	free(process);
}

void process_reparent_children(struct process *proc)
{
	scoped_lock g{proc->children_lock};

	/* In POSIX, reparented children get to be children of PID 1 */
	process *new_parent = first_process;

	if(!proc->children)
	{
		return;
	}

	for(process *c = proc->children; c != nullptr; c = c->next_sibbling)
		c->parent = new_parent; 
	
	process_append_children(new_parent, proc->children);
}

extern "C" void process_kill_other_threads(void)
{
	process *current = get_current_process();
	thread *current_thread = get_current_thread();
	unsigned long threads_to_wait_for = 0;
	/* TODO: Fix thread killing */
	list_for_every(&current->thread_list)
	{
		thread *t = container_of(l, thread, thread_list_head);
		if(t == current_thread)
			continue;
		t->flags |= THREAD_SHOULD_DIE;
		threads_to_wait_for++;
	}

	while(current->nr_threads != 1)
		cpu_relax();
}

void process_destroy(thread_t *current_thread)
{
	process *current = get_current_process();
	process_kill_other_threads();

	process_destroy_file_descriptors(current);

	/* We destroy the address space after fds because some close() routines may require address space access */
	process_destroy_aspace();

	process_reparent_children(current);

	for(proc_event_sub *s = current->sub_queue; s; s = s->next)
	{
		s->valid_sub = false;
	}

	/* Set this in this order exactly */
	current_thread->flags = THREAD_IS_DYING;
	current_thread->status = THREAD_DEAD;

	/* Finally, wake up any possible concerned (waiting :D) parents */
	sem_signal(&current->parent->wait_sem);

	/* TODO: We need to send an actual SIGCHILD (look at the siginfo structure) */
	kernel_raise_signal(SIGCHLD, current->parent, 0, nullptr);

	sched_yield();

	while(true);
}

int process_attach(process *tracer, process *tracee)
{
	/* You can't attach to yourself */
	if(tracer == tracee)
		return errno = ESRCH, -1;
	/* TODO: Enforce process permissions */
	if(!tracer->tracees.ptr)
	{
		tracer->tracees.ptr = tracee;
	}
	else
	{
		if(extrusive_list_add(&tracer->tracees, tracee) < 0)
			return errno = ENOMEM, -1;
	}
	return 0;
}

/* Finds a pid that tracer is tracing */
struct process *process_find_tracee(process *tracer, pid_t pid)
{
	extrusive_list_head *list = &tracer->tracees;
	while(list && list->ptr)
	{
		process *tracee = (process *) list->ptr;
		if(tracee->pid == pid)
			return tracee;
		list = list->next;
	}
	return nullptr;
}

void process_add_thread(process *proc, thread_t *thread)
{
	scoped_lock g{proc->thread_list_lock};

	list_add_tail(&thread->thread_list_head, &proc->thread_list);

	proc->nr_threads++;
}

extern "C" void sys_exit_thread(int value)
{
	/* Okay, so the libc called us. That means we can start destroying the thread */
	/* NOTE: I'm not really sure if musl destroyed the user stack and fs,
	 * and if we should anything to free them */

	thread *thread = get_current_thread();
	if(thread->ctid)
	{
		pid_t value = 0;
		if(copy_to_user(thread->ctid, &value, sizeof(value)) < 0)
			goto skip;
		futex_wake((int *) thread->ctid, INT_MAX);
	}
skip:	
	/* Destroy the thread */
	thread_exit();
	/* aaaaand we'll never return back to user-space, so just hang on */
	sched_yield();
}

void process_increment_stats(bool is_kernel)
{
	struct process *process = get_current_process();
	/* We're not in a process, return! */
	if(!process)
		return;
	if(is_kernel)
		process->system_time++;
	else
		process->user_time++;
}
