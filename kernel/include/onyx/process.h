/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PROCESS_H
#define _PROCESS_H

#include <sys/types.h>

#include <onyx/vmm.h>
#include <onyx/mutex.h>
#include <onyx/ioctx.h>
#include <onyx/spinlock.h>
#include <onyx/task_switching.h>
#include <onyx/signal.h>
#include <onyx/registers.h>
#include <onyx/list.h>

#include <onyx/elf.h>

struct futex;
#define THREADS_PER_PROCESS 30

struct proc_event_sub;

struct process
{
	/* Signal specific flags */
	int signal_pending;

	/* The next process in the linked list */
	struct process *next;

	/* The processes' threads */
	thread_t *threads[30];
	
	/* Kernel-side errno of the process */
	/* TODO: Should this be kept on the thread_t structure? */
	int errno;

	struct mm_address_space address_space;
	/* Program name*/
	char *cmd_line;

	/* IO Context of the process */
	ioctx_t ctx;

	/* Process ID */
	pid_t pid;
	
	/* exit(2) specific flags */
	int has_exited;
	int exit_code;
	
	/* Process' UID and GID */
	uid_t uid;
	gid_t gid;
	uid_t euid;
	gid_t egid; 
	
	/* Signal register save */
	registers_t old_regs;

	/* Pointer to the VDSO */
	void *vdso;

	/* Signal tables */
	struct mutex signal_lock;
	struct sigaction sigtable[_NSIG];

	/* Signal mask */
	sigset_t sigmask;
	
	/* Pending signal set */
	sigset_t pending_set;
	
	/* Information about the current signal */
	struct signal_info sinfo;

	/* Process personality */
	unsigned long personality;

	/* This process' parent */
	struct process *parent;
	
	/* Linked list to the processes being traced */
	struct list_head tracees;

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
};

#ifdef __cplusplus
extern "C" {
#endif

struct process *process_create(const char *cmd_line, ioctx_t *ctx, struct process *parent);
void process_create_thread(struct process *proc, thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp);
int process_fork_thread(thread_t *src, struct process *dest, syscall_ctx_t *ctx);
struct process *get_process_from_pid(pid_t pid);
void process_destroy_aspace(void);
int process_attach(struct process *tracer, struct process *tracee);
struct process *process_find_tracee(struct process *tracer, pid_t pid);
void process_exit_from_signal(int signum);
char **process_copy_envarg(char **envarg, _Bool to_kernel, int *count);
void process_increment_stats(bool is_kernel);
void process_continue(struct process *p);
void process_stop(struct process *p);

#ifdef __cplusplus
}
#endif

static inline struct process *get_current_process()
{
	thread_t *thread = get_current_thread();
	return (thread == NULL) ? NULL : (struct process*) thread->owner;
}

#endif
