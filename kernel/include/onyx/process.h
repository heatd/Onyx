/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_PROCESS_H
#define _ONYX_PROCESS_H

#include <sys/types.h>

#include <onyx/vm.h>
#include <onyx/mutex.h>
#include <onyx/ioctx.h>
#include <onyx/spinlock.h>
#include <onyx/signal.h>
#include <onyx/registers.h>
#include <onyx/list.h>
#include <onyx/scheduler.h>
#include <onyx/condvar.h>
#include <onyx/semaphore.h>
#include <onyx/elf.h>
#include <onyx/syscall.h>
#include <onyx/cred.h>
#include <onyx/itimer.h>
#include <onyx/wait_queue.h>
#include <onyx/vm_layout.h>
#include <onyx/rwlock.h>


#include <sys/resource.h>

struct proc_event_sub;

struct process_group;

#ifdef __cplusplus
extern "C" {
#endif

static void process_get(struct process *process);
static void process_put(struct process *process);

#ifdef __cplusplus
}
#endif

#define PROCESS_FORKED    (1 << 0)

struct process
{
	unsigned long refcount;

	unsigned long flags;

	/* The next process in the linked list */
	struct process *next;

	unsigned long nr_threads;

	struct list_head thread_list;
	struct spinlock thread_list_lock;

	struct mm_address_space address_space;
	/* Program name*/
	char *cmd_line;

	/* IO Context of the process */
	struct ioctx ctx;

	/* Process ID */
	pid_t pid;

	/* Process' UID and GID */
	struct creds cred;

	/* Pointer to the VDSO */
	void *vdso;

	/* Signal information */
	struct spinlock signal_lock;
	struct k_sigaction sigtable[_NSIG];
	unsigned int signal_group_flags;
	struct wait_queue wait_child_event;
	unsigned int exit_code;

	/* Process personality */
	unsigned long personality;

	/* This process' parent */
	struct process *parent;

	/* Linked list to the processes being traced */
	struct extrusive_list_head tracees;

	/* User time and system time consumed by the process */
	hrtime_t user_time;
	hrtime_t system_time;
	hrtime_t children_utime;
	hrtime_t children_stime;

	/* proc_event queue */
	struct spinlock sub_queue_lock;
	struct proc_event_sub *sub_queue;
	unsigned long nr_subs;
	unsigned long nr_acks;

	void *interp_base;
	void *image_base;

	struct elf_info info;

	struct cond syscall_cond;
	struct mutex condvar_mutex;

	struct spinlock children_lock;
	struct process *children, *prev_sibbling, *next_sibbling;

	struct itimer timers[ITIMER_COUNT];

	struct spinlock pgrp_lock;
	struct list_head pgrp_node;
	struct process_group *process_group;

	struct rlimit rlimits[RLIM_NLIMITS + 1];
	struct rwlock rlimit_lock;

#ifdef __cplusplus
	process();
	~process();

	void ref()
	{
		process_get(this);
	}

	void unref()
	{
		process_put(this);
	}

	bool route_signal(struct sigpending *pend);

	void remove_thread(thread *t)
	{
		scoped_lock g{thread_list_lock};

		nr_threads--;

		list_remove(&t->thread_list_head);
	}

	int rlimit(int rsrc, struct rlimit *old, const struct rlimit *new_lim, unsigned int flags);

	struct rlimit get_rlimit(int rsrc);

	void init_default_limits();
	void inherit_limits(process *parent);
#endif

};

#ifdef __cplusplus
extern "C" {
#endif

struct process *process_create(const char *cmd_line, struct ioctx *ctx, struct process *parent);

struct thread *process_create_main_thread(struct process *proc, thread_callback_t callback, void *sp);

struct process *get_process_from_pid(pid_t pid);
struct thread *process_fork_thread(thread_t *src, struct process *dest, struct syscall_frame *ctx);
void process_destroy_aspace(void);
int process_attach(struct process *tracer, struct process *tracee);
struct process *process_find_tracee(struct process *tracer, pid_t pid);

void process_end(struct process *p);
void process_add_thread(struct process *process, thread_t *thread);
char **process_copy_envarg(const char **envarg, bool to_kernel, int *count);

static inline void process_get(struct process *process)
{
	__atomic_add_fetch(&process->refcount, 1, __ATOMIC_ACQUIRE);
}

static inline void process_put(struct process *process)
{
	if(__atomic_sub_fetch(&process->refcount, 1, __ATOMIC_ACQUIRE) == 0)
		process_end(process);
}

struct stack_info
{
	void *base;
	void *top;
	size_t length;
};

int process_alloc_stack(struct stack_info *info);

#ifdef __cplusplus
}
#endif

static inline struct process *get_current_process()
{
	thread_t *thread = get_current_thread();
	return (thread == NULL) ? NULL : (struct process *) thread->owner;
}

static inline struct mm_address_space *get_current_address_space()
{
	struct process *proc = get_current_process();
	return proc ? &proc->address_space : NULL;
}

#ifdef __cplusplus

#include <onyx/auto_resource.h>

using auto_process = auto_resource<process>;

using process_visit_function_t = bool (*)(process *, void *);

void for_every_process(process_visit_function_t func, void *ctx);


/* I took this idea from linux :P */
#define RUSAGE_BOTH    -2

int do_rusage(int who, rusage *usage, process *p);

void notify_process_stop_cont(process *proc, int signum);

template <typename Callable>
void process_for_every_thread_unlocked(process *p, Callable cb)
{

	list_for_every(&p->thread_list)
	{
		thread *t = container_of(l, struct thread, thread_list_head);

		if(!cb(t))
			return;
	}
}

template <typename Callable>
void process_for_every_thread(process *p, Callable cb)
{
	scoped_lock g{p->thread_list_lock};

	process_for_every_thread_unlocked(p, cb);
}

[[noreturn]]
void process_exit_from_signal(int signum);


#endif

#endif
