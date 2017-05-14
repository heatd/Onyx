/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PROCESS_H
#define _PROCESS_H

#include <sys/types.h>

#include <kernel/vmm.h>
#include <kernel/ioctx.h>
#include <kernel/spinlock.h>
#include <kernel/task_switching.h>
#include <kernel/signal.h>
#include <kernel/registers.h>
#define THREADS_PER_PROCESS 30
typedef struct proc
{
	int signal_pending;
	int signal_dispatched;
	struct proc *next;
	thread_t *threads[30];
	uint64_t data_area;
	int errno;
	avl_node_t *tree;
	char *cmd_line;
	ioctx_t ctx;
	pid_t pid;
	uintptr_t fs;
	PML4 *cr3;
	void *brk;
	int has_exited;
	int exit_code;
	uid_t uid;
	gid_t gid;
	uid_t setuid;
	gid_t setgid;
	spinlock_t vm_spl;
	registers_t old_regs;
	sighandler_t sighandlers[27];
	void *sigreturn;
	void *vdso;
	unsigned long personality;
	struct signal_info sinfo;
	struct proc *parent;
} process_t;
process_t *process_create(const char *cmd_line, ioctx_t *ctx, process_t *parent);
void process_create_thread(process_t *proc, thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp);
void process_fork_thread(process_t *dest, process_t *src, int thread_index);
process_t *get_process_from_pid(pid_t pid);
extern volatile process_t *current_process;
inline process_t *get_current_process()
{
	return (process_t*) current_process;
}
#endif
