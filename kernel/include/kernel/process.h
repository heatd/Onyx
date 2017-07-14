/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PROCESS_H
#define _PROCESS_H

#include <sys/types.h>

#include <kernel/vmm.h>
#include <kernel/mutex.h>
#include <kernel/ioctx.h>
#include <kernel/spinlock.h>
#include <kernel/task_switching.h>
#include <kernel/signal.h>
#include <kernel/registers.h>
#include <kernel/list.h>
#define THREADS_PER_PROCESS 30
typedef struct proc
{
	/* Signal specific flags */
	int signal_pending;

	/* The next process in the linked list */
	struct proc *next;

	/* The processes' threads */
	thread_t *threads[30];
	
	/* Kernel-side errno of the process */
	/* TODO: Should this be kept on the thread_t structure? */
	int errno;

	/* Virtual address space AVL tree */
	avl_node_t *tree;
	spinlock_t vm_spl;
	/* Program name*/
	char *cmd_line;

	/* IO Context of the process */
	ioctx_t ctx;

	/* Process ID */
	pid_t pid;
	
	/* Paging specific pointer */
	PML4 *cr3;
	
	/* Process' brk */
	void *brk;
	
	/* exit(2) specific flags */
	int has_exited;
	int exit_code;
	
	/* Process' UID and GID */
	uid_t uid;
	gid_t gid;
	
	/* Signal register save */
	registers_t old_regs;

	/* Pointer to the VDSO */
	void *vdso;

	/* Signal tables */
	mutex_t signal_lock;
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
	struct proc *parent;
	
	/* Linked list to the processes being traced */
	struct list_head tracees;
	
	/* mmap(2) base */
	void *mmap_base;

} process_t;
process_t *process_create(const char *cmd_line, ioctx_t *ctx, process_t *parent);
void process_create_thread(process_t *proc, thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp);
void process_fork_thread(process_t *dest, process_t *src, int thread_index);
process_t *get_process_from_pid(pid_t pid);
void process_destroy_aspace(void);
int process_attach(process_t *tracer, process_t *tracee);
process_t *process_find_tracee(process_t *tracer, pid_t pid);
void process_exit_from_signal(int signum);
char **process_copy_envarg(char **envarg, _Bool to_kernel, int *count);
extern volatile process_t *current_process;
static inline process_t *get_current_process()
{
	return (process_t*) current_process;
}
#endif
