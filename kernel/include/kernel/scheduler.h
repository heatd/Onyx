/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SCHEDULER_H
#define _KERNEL_SCHEDULER_H

#include <stdint.h>
#include <stdbool.h>

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
	bool woken_up_by_futex;
	/* And arch dependent stuff in this ifdef */
#ifdef __x86_64__
	void *fs;
	void *gs;
#endif
} thread_t;

int sched_init(void);
thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void* args);
thread_t* sched_create_main_thread(thread_callback_t callback, uint32_t flags,int argc, char **argv, char **envp);
void sched_remove_thread(thread_t *thread);
thread_t *get_current_thread(void);
void* sched_switch_thread(void* last_stack);
void sched_sleep(unsigned long ms);
void sched_yield(void);
void thread_add(thread_t *add);
void set_current_thread(thread_t *t);
void thread_destroy(thread_t *t);
void thread_set_state(thread_t *thread, int state);
void thread_wake_up(thread_t *thread);
bool sched_is_preemption_disabled(void);
void sched_change_preemption_state(bool disable);
void sched_sleep_until_wake(void);
void thread_wake_up_ftx(thread_t *thread);
void thread_reset_futex_state(thread_t *thread);
#endif
