/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PROCESS_H
#define _PROCESS_H

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

struct futex;

struct proc_event_sub;

struct process
{
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
	
	/* exit(2) specific flags */
	int has_exited;

	struct semaphore wait_sem;
	int exit_code;
	
	/* Process' UID and GID */
	struct creds cred;

	/* Pointer to the VDSO */
	void *vdso;

	/* Signal tables */
	struct mutex signal_lock;
	struct sigaction sigtable[_NSIG];

	/* Process personality */
	unsigned long personality;

	/* This process' parent */
	struct process *parent;
	
	/* Linked list to the processes being traced */
	struct extrusive_list_head tracees;

	/* Futex queue */
	struct futex *futex_queue;

	/* Futex queue lock */
	struct spinlock futex_queue_lock;
	/* User time and system time consumed by the process */
	clock_t user_time;
	clock_t system_time;

	/* proc_event queue */
	struct spinlock sub_queue_lock;
	struct proc_event_sub *sub_queue;
	unsigned long nr_subs;
	unsigned long nr_acks;

	void *image_base;

	struct elf_info info;

	struct cond syscall_cond;
	struct mutex condvar_mutex;

	struct spinlock children_lock;
	struct process *children, *prev_sibbling, *next_sibbling;
};

#ifdef __cplusplus
extern "C" {
#endif

struct process *process_create(const char *cmd_line, struct ioctx *ctx, struct process *parent);
struct thread *process_create_thread(struct process *proc, thread_callback_t callback,
		uint32_t flags, int argc, char **argv, char **envp);
struct process *get_process_from_pid(pid_t pid);
void process_destroy_aspace(void);
int process_attach(struct process *tracer, struct process *tracee);
struct process *process_find_tracee(struct process *tracer, pid_t pid);
void process_exit_from_signal(int signum);
char **process_copy_envarg(char **envarg, bool to_kernel, int *count);
void process_increment_stats(bool is_kernel);
void process_continue(struct process *p);
void process_stop(struct process *p);

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
	return &get_current_process()->address_space;
}

#endif
