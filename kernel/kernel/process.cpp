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
#include <onyx/proc_event.h>
#include <onyx/syscall.h>
#include <onyx/futex.h>
#include <onyx/utils.h>
#include <onyx/scoped_lock.h>
#include <onyx/pgrp.h>

#include <pthread_kernel.h>

#include <sys/wait.h>

extern PML *current_pml4;
ids *process_ids = nullptr;

process *first_process = nullptr;
static process *process_tail = nullptr;
static spinlock process_list_lock;

[[noreturn]]
void process_exit(unsigned int exit_code);
void process_end(process *process);

void process_append_children(process *parent, process *children)
{
	scoped_lock g{parent->children_lock};

	process **pp = &parent->children;
	process *p = nullptr;

	while(*pp)
	{
		p = *pp;
		pp = &p->next_sibbling;
	}

	*pp = children;

	children->prev_sibbling = p;
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

process::process() : pgrp_node{this}
{
	init_wait_queue_head(&this->wait_child_event);
	mutex_init(&condvar_mutex);
	mutex_init(&ctx.fdlock);
	rwlock_init(&rlimit_lock);
}

process::~process()
{
	process_group->remove_process(this);
}

process *process_create(const char *cmd_line, ioctx *ctx, process *parent)
{
	/* FIXME: Failure here kinda sucks and is probably super leaky */
	if(unlikely(!process_ids))
	{
		process_ids = idm_add("pid", 1, UINTMAX_MAX);
		assert(process_ids != nullptr);
	}

	auto proc = new process;
	if(!proc)
		return errno = ENOMEM, nullptr;
	
	/* TODO: idm_get_id doesn't wrap? POSIX COMPLIANCE */
	proc->refcount = 1;
	proc->pid = idm_get_id(process_ids);
	assert(proc->pid != (pid_t) -1);
	proc->cmd_line = strdup(cmd_line);
	creds_init(&proc->cred);

	itimer_init(proc);

	if(!proc->cmd_line)
	{
		delete proc;
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
			delete proc;
			return nullptr;
		}
	}
	else
	{
		if(allocate_file_descriptor_table(proc) < 0)
		{
			delete proc;
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
		proc->image_base = parent->image_base;
		proc->interp_base = parent->interp_base;
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

		parent->process_group->inherit(proc);
		proc->flags = parent->flags;

		proc->inherit_limits(parent);
	}
	else
	{
		proc->process_group = pgrp_create(proc);
		if(!proc->process_group)
			return nullptr;

		/* This makes me uncomfortable... We create the object(ref 1), add ourselves(ref again)
		 * only to unref it so the reference count goes back to normal... kind of yuck.
		 */

		proc->process_group->add_process(proc);

		proc->process_group->unref();

		proc->init_default_limits();
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
		return 0;
}

bool process_found_children(pid_t pid, process *proc)
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

void process_remove_from_list(process *process);

template <typename Callable>
static void for_every_child(process *proc, Callable cb)
{
	scoped_lock g{proc->children_lock};

	for(process *p = proc->children; p != nullptr; p = p->next_sibbling)
	{
		if(cb(p) == false)
			break;
	}
}

pid_t process_get_pgid(process *p)
{
	scoped_lock g{p->pgrp_lock};
	return p->process_group->get_pid();
}

#define WAIT_INFO_MATCHING_ANY         (1 << 0)
#define WAIT_INFO_MATCH_PGID           (1 << 1)

struct wait_info
{
	int wstatus;
	rusage usage;
	pid_t pid;
	int status;
	unsigned int flags;
	unsigned int options;

	wait_info(pid_t pid, unsigned int options) : wstatus{}, usage{},
	          pid{pid}, status{-ECHILD}, flags{}, options{options}
	{
		/* pid = -1: matches any process;
		 * pid < 0: matches processes with pgid = -pid;
		 * pid = 0: matches processes with pgid = process' pgid.
		 * pid > 0: matches processes with pid = pid.
		 */
		if(pid == -1)
		{
			flags |= WAIT_INFO_MATCHING_ANY;
		}
		else if(pid < 0)
		{
			flags |= WAIT_INFO_MATCH_PGID;
			this->pid = -pid;
		}
		else if(pid == 0)
		{
			auto current = get_current_process();

			this->pid = process_get_pgid(current);
 
			flags |= WAIT_INFO_MATCH_PGID;
		}

		/* WEXITED is always implied for wait4 */
		this->options |= WEXITED;
	}

	bool reap_wait() const
	{
		return !(options & WNOWAIT);
	}
};

bool wait_matches_process(const wait_info& info, process *proc)
{
	if(info.flags & WAIT_INFO_MATCHING_ANY)
		return true;

	if(info.flags & WAIT_INFO_MATCH_PGID && process_get_pgid(proc) == info.pid)
		return true;

	if(info.pid == proc->pid)
		return true;

	return false;
}

int do_getrusage(int who, rusage *usage, process *proc)
{
	memset(usage, 0, sizeof(rusage));
	hrtime_t utime = 0;
	hrtime_t stime = 0;

	switch(who)
	{
		case RUSAGE_BOTH:
		case RUSAGE_CHILDREN:
			utime = proc->children_utime;
			stime = proc->children_stime;

			if(who == RUSAGE_CHILDREN)
				break;

		[[fallthrough]];
		case RUSAGE_SELF:
			utime += proc->user_time;
			stime += proc->system_time;
			break;
		
		default:
			return -EINVAL;
	}

	hrtime_to_timeval(utime, &usage->ru_utime);
	hrtime_to_timeval(stime, &usage->ru_stime);
	return 0;
}

extern "C"
int sys_getrusage(int who, rusage *user_usage)
{
	/* do_getrusage understands this flag but it isn't supposed to be exposed */
	if(who == RUSAGE_BOTH)
		return -EINVAL;

	rusage kusage;
	int st = 0;
	if((st = do_getrusage(who, &kusage, get_current_process())) < 0)
		return st;
	
	return copy_to_user(user_usage, &kusage, sizeof(rusage));
}

void process_accumulate_rusage(process *child, const rusage &usage)
{
	auto us = get_current_process();

	__atomic_add_fetch(&us->children_stime, timeval_to_hrtime(&usage.ru_stime), __ATOMIC_RELAXED);
	__atomic_add_fetch(&us->children_utime, timeval_to_hrtime(&usage.ru_utime), __ATOMIC_RELAXED);
}

bool process_wait_exit(process *child, wait_info& winfo)
{
	if(!(child->signal_group_flags & SIGNAL_GROUP_EXIT))
		return false;

	scoped_lock g{child->signal_lock};

	if(!(child->signal_group_flags & SIGNAL_GROUP_EXIT))
		return false;

	if(!(winfo.options & WEXITED))
		return false;

	do_getrusage(RUSAGE_BOTH, &winfo.usage, child);

	winfo.pid = child->pid;

	winfo.wstatus = child->exit_code;

	if(winfo.reap_wait())
	{
		auto current = get_current_process();
		process_accumulate_rusage(child, winfo.usage);
		spin_unlock(&current->children_lock);
		g.unlock();
		process_put(child);
		spin_lock(&current->children_lock);
	}

	return true;
}

bool process_wait_stop(process *child, wait_info& winfo)
{
	if(!(child->signal_group_flags & SIGNAL_GROUP_STOPPED))
		return false;

	scoped_lock g{child->signal_lock};

	if(!(child->signal_group_flags & SIGNAL_GROUP_STOPPED))
		return false;

	if(child->signal_group_flags & SIGNAL_GROUP_EXIT)
		return false;

	if(!(winfo.options & WSTOPPED))
		return false;
	
	/* We use exit_code = 0 to know it has been reaped */
	if(!child->exit_code)
		return false;
	
	do_getrusage(RUSAGE_BOTH, &winfo.usage, child);

	winfo.pid = child->pid;

	winfo.wstatus = child->exit_code;

	if(winfo.reap_wait())
	{
		child->exit_code = 0;
	}

	return true;
}

bool process_wait_cont(process *child, wait_info& winfo)
{
	if(!(child->signal_group_flags & SIGNAL_GROUP_CONT))
		return false;

	scoped_lock g{child->signal_lock};

	if(!(child->signal_group_flags & SIGNAL_GROUP_CONT))
		return false;
	
	if(child->signal_group_flags & SIGNAL_GROUP_EXIT)
		return false;

	if(!(winfo.options & WCONTINUED))
		return false;
	
	do_getrusage(RUSAGE_BOTH, &winfo.usage, child);

	winfo.pid = child->pid;

	winfo.wstatus = child->exit_code;

	if(winfo.reap_wait())
	{
		child->signal_group_flags &= ~SIGNAL_GROUP_CONT;
	}

	return true;
}

#define WINFO_STATUS_OK     1
#define WINFO_STATUS_NOHANG 2

bool wait_handle_processes(process *proc, wait_info& winfo)
{
	winfo.status = -ECHILD;
	for_every_child(proc, [&](process *child) -> bool
	{
		if(!wait_matches_process(winfo, child))
			return true;
		
		winfo.status = 0;

		if(!process_wait_exit(child, winfo)
		   && !process_wait_stop(child, winfo)
		   && !process_wait_cont(child, winfo))
		{
			return true;
		}

		winfo.status = WINFO_STATUS_OK;

		/* We'll want to stop iterating after waiting for a child */
		return false;
	});

	if(winfo.status != WINFO_STATUS_OK && winfo.options & WNOHANG)
		winfo.status = WINFO_STATUS_NOHANG;

#if 0
	printk("winfo status: %d\n", winfo.status);
#endif

	return winfo.status != 0;
}

#define VALID_WAIT4_OPTIONS  (WNOHANG | WUNTRACED | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT)

extern "C" pid_t sys_wait4(pid_t pid, int *wstatus, int options, rusage *usage)
{
	auto current = get_current_process();

	if(options & ~VALID_WAIT4_OPTIONS)
		return -EINVAL;

	wait_info w{pid, (unsigned int) options};
	
	int st = wait_for_event_interruptible(&current->wait_child_event, wait_handle_processes(current, w));

#if 0
	printk("st %d w.status %d\n", st, w.status);
#endif

	if(st < 0)
		return st;
	
	if(w.status != WINFO_STATUS_OK)
		return w.status == WINFO_STATUS_NOHANG ? 0 : w.status;

#if 0
	printk("w.wstatus: %d\n", w.wstatus);
#endif

	if((wstatus && copy_to_user(wstatus, &w.wstatus, sizeof(int)) < 0)
	    || (usage && copy_to_user(usage, &w.usage, sizeof(rusage)) < 0))
	{
		return -EFAULT;
	}

	return w.pid;
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

	child->flags |= PROCESS_FORKED;
	
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

#define W_STOPPING   0x7f
#define W_CORE_DUMPED (1 << 7)
#define W_SIG(sig) (signum)
#define W_STOPPED_SIG(sig) (W_STOPPING | (sig << 8))
#define W_CONTINUED 0xffff
#define W_EXIT_CODE(code) ((code & 0xff) << 8)

/* Wait status layout:
 * For exits: bits 0-7: MBZ;
 *            bits 8-15: Exit code & 0xff
 * For signal stops: bits 0-7: 0x7f
 *                   bits 8-15: Stopping signal
 * For signal conts: bits 0-15: 0xffff
 * For signal termination: bits 0-6: Signal number
 *                         bit 7: Set on core dumps
 * Any range of bits that's not specified here *must be zero*.
 */
int make_wait4_wstatus(int signum, bool core_dumped, int exit_code)
{
	int wstatus = core_dumped ? W_CORE_DUMPED : 0;

	if(signum == 0)
	{
		wstatus |= W_EXIT_CODE(exit_code);
	}
	else
	{
		if(signal_is_stopping(signum))
		{
			wstatus |= W_STOPPED_SIG(signum);
		}
		else if(signum == SIGCONT)
		{
			wstatus |= W_CONTINUED;
		}
		else
			wstatus |= signum; 
	}

	return wstatus;
}

[[noreturn]]
void process_exit_from_signal(int signum)
{
	process_exit(make_wait4_wstatus(signum, false, 0));
}

extern "C" void sys_exit(int status)
{
	status &= 0xff;
	process_exit(make_wait4_wstatus(0, false, status));
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

void process_destroy_file_descriptors(process *process)
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

void process_remove_from_list(process *proc)
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

void process_wait_for_dead_threads(process *process)
{
	while(process->nr_threads)
	{
		cpu_relax();
	}
}

void process_end(process *process)
{
	process_remove_from_list(process);

	process_wait_for_dead_threads(process);

	free(process->cmd_line);
	process->cmd_line = nullptr;
	
	if(process->ctx.cwd)
		fd_put(process->ctx.cwd);

	delete process;
}

void process_reparent_children(process *proc)
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

void process_kill_other_threads(void)
{
	process *current = get_current_process();
	thread *current_thread = get_current_thread();

	process_for_every_thread(current, [&](thread *t) -> bool
	{
		if(t == current_thread)
			return true;

		scoped_lock g{t->sinfo.lock};

		t->sinfo.flags |= THREAD_SIGNAL_EXITING;

		/* If it's in an interruptible sleep, very good. Else, it's either
		 * in an uninterruptible sleep or it was stopped but got woken up by SIGKILL code before us.
		 * It's impossible for a process to otherwise exit without every thread already
		 * being SIGCONT'd.
		 */
		if(t->status == THREAD_INTERRUPTIBLE)
			thread_wake_up(t);
		
		return true;
	});

	while(current->nr_threads != 1)
		cpu_relax();
}

[[noreturn]]
void process_exit(unsigned int exit_code)
{
	auto current_thread = get_current_thread();
	process *current = get_current_process();

	if(current->pid == 1)
	{
		printk("Panic: %s exited with exit code %u!\n",
			current->cmd_line, exit_code);
		ENABLE_INTERRUPTS();
		for(;;);
	}

	process_kill_other_threads();

	process_destroy_file_descriptors(current);

	current->signal_group_flags |= SIGNAL_GROUP_EXIT;

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

	{

	scoped_lock g{current->signal_lock};
	current->exit_code = exit_code;

	/* Finally, wake up any possible concerned parents */
	wait_queue_wake_all(&current->parent->wait_child_event);

	}

	siginfo_t info = {};

	info.si_signo = SIGCHLD;
	info.si_pid = current->pid;
	info.si_uid = current->cred.ruid;
	info.si_stime = current->system_time / NS_PER_MS;
	info.si_utime = current->user_time / NS_PER_MS;

	if(WIFEXITED(exit_code))
	{
		info.si_code = CLD_EXITED;
		info.si_status = WEXITSTATUS(exit_code);
	}
	else if(WIFSIGNALED(exit_code))
	{
		info.si_code = CLD_KILLED;
		info.si_status = WTERMSIG(exit_code);
	}

	kernel_raise_signal(SIGCHLD, current->parent, 0, &info);

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
process *process_find_tracee(process *tracer, pid_t pid)
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
		pid_t to_write = 0;
		if(copy_to_user(thread->ctid, &to_write, sizeof(to_write)) < 0)
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
	process *process = get_current_process();
	/* We're not in a process, return! */
	if(!process)
		return;
	if(is_kernel)
		process->system_time++;
	else
		process->user_time++;
}

void for_every_process(process_visit_function_t func, void *ctx)
{
	scoped_lock g{process_list_lock};

	auto p = first_process;

	while(p != nullptr)
	{
		if(!func(p, ctx))
			return;
		
		p = p->next;
	}
}

void notify_process_stop_cont(process *proc, int signum)
{
	auto parent = proc->parent;

	/* init might get a SIGSTOP? idk */
	if(!parent)
		return;
	
	auto code = make_wait4_wstatus(signum, false, 0);

	proc->exit_code = code;

	wait_queue_wake_all(&parent->wait_child_event);

	siginfo_t info = {};
	info.si_code = signal_is_stopping(signum) ? CLD_STOPPED : CLD_CONTINUED;
	info.si_signo = SIGCHLD;
	info.si_pid = proc->pid;
	info.si_uid = proc->cred.ruid;
	info.si_stime = proc->system_time / NS_PER_MS;
	info.si_utime = proc->user_time / NS_PER_MS;
	info.si_status = signum;

	kernel_raise_signal(SIGCHLD, parent, 0, &info);
}

bool process::route_signal(struct sigpending *pend)
{
	scoped_lock g{thread_list_lock};
	bool done = false;

	/* Oh no, we're not going to be able to route this! */
	if(nr_threads == 0)
		return false;
	
	process_for_every_thread_unlocked(this, [&](thread *t) -> bool
	{
		auto& sinfo = t->sinfo;

		if(sinfo.try_to_route(pend))
		{
			done = true;
			return false;
		}

		return true;
	});

	auto first_elem = list_first_element(&thread_list);

	assert(first_elem != nullptr);

	auto first_t = container_of(first_elem, struct thread, thread_list_head);

	return first_t->sinfo.add_pending(pend);
}

namespace onx
{

namespace handle
{

expected<file *, int > process_handle_opener(unsigned int rsrc_type, unsigned long id, int flags)
{
	return unexpected<int>{-ESRCH};	
}

}

}
