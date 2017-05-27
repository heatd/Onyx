/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _TASK_SWITCHING_AMD64_H
#define _TASK_SWITCHING_AMD64_H
#include <stdint.h>

#include <kernel/registers.h>
#include <kernel/fpu.h>
#define THREAD_RUNNABLE 0
#define THREAD_SLEEPING 1

typedef void(*thread_callback_t)(void*);
struct proc;
typedef struct thr
{
	/* Put arch-independent stuff right here */
	uintptr_t *user_stack;
	uintptr_t *kernel_stack;
	uintptr_t *kernel_stack_top;
	uintptr_t *user_stack_bottom;
	volatile struct proc *owner;
	thread_callback_t rip;
	uint32_t flags;
	int id;
	int status;
	struct thr *next;
	uint64_t timestamp;
	unsigned long sleeping_for;
	unsigned char *fpu_area;
	/* And arch dependent stuff in this ifdef */
#ifdef __x86_64__
	void *fs;
	void *gs;
#endif
} thread_t;

int sched_init(void);
thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void* args);
thread_t* sched_create_main_thread(thread_callback_t callback, uint32_t flags,int argc, char **argv, char **envp);
void sched_destroy_thread(thread_t *thread);
thread_t *get_current_thread();
uintptr_t *sched_fork_stack(syscall_ctx_t *ctx, uintptr_t *stack);
void* sched_switch_thread(void* last_stack);
void sched_sleep(unsigned long ms);
void sched_yield();
void thread_add(thread_t *add);
void set_current_thread(thread_t *t);
#endif
