/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SCHEDULER_H
#define _KERNEL_SCHEDULER_H

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <onyx/spinlock.h>
#include <onyx/signal.h>
#include <onyx/list.h>

#define NUM_PRIO 40

#define SCHED_PRIO_VERY_LOW	0
#define SCHED_PRIO_LOW		10
#define SCHED_PRIO_NORMAL	20
#define SCHED_PRIO_HIGH		30
#define SCHED_PRIO_VERY_HIGH	39

typedef void (*thread_callback_t)(void*);
struct process;

typedef struct thread
{
	unsigned long refcount;
	/* Put arch-independent stuff right here */
	uintptr_t *user_stack;
	uintptr_t *kernel_stack;
	uintptr_t *kernel_stack_top;
	uintptr_t *user_stack_bottom;
	struct process *owner;
	thread_callback_t rip;
	uint32_t flags;
	int id;
	int status;
	int priority;
	unsigned int cpu;
	struct thread *next;
	struct thread *prev_prio, *next_prio;
	struct thread *prev_wait, *next_wait;
	unsigned char *fpu_area;
	bool woken_up_by_futex;
	struct thread *sem_prev;
	struct thread *sem_next;
	struct spinlock lock;
	struct spinlock *to_release;
	int errno_val;
	struct signal_info sinfo;
	struct list_head thread_list_head;
	unsigned long addr_limit;
	/* And arch dependent stuff in this ifdef */
#ifdef __x86_64__
	void *fs;
	void *gs;
#endif
} thread_t;

#define THREAD_KERNEL			(1 << 0)
#define THREAD_NEEDS_RESCHED	(1 << 1)
#define THREAD_IS_DYING			(1 << 2)
#define THREAD_SHOULD_DIE		(1 << 3)
#define THREAD_ACTIVE			(1 << 4)

#ifdef __cplusplus
extern "C" {
#endif

int sched_init(void);

thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void* args);

thread_t* sched_create_main_thread(thread_callback_t callback, uint32_t flags,int argc, char **argv, char **envp);

void sched_remove_thread(thread_t *thread);

thread_t *get_current_thread(void);

void* sched_switch_thread(void* last_stack);

void sched_sleep(unsigned long ms);

void sched_yield(void);

void thread_add(thread_t *add, unsigned int cpu);

void set_current_thread(thread_t *t);

void thread_destroy(thread_t *t);

void thread_set_state(thread_t *thread, int state);

void thread_wake_up(thread_t *thread);

bool sched_is_preemption_disabled(void);

void sched_sleep_until_wake(void);

void thread_wake_up_ftx(thread_t *thread);

void thread_reset_futex_state(thread_t *thread);

void sched_start_thread(thread_t *thread);

void sched_wake_up_available_threads(void);

void sched_enable_preempt(void);

void sched_disable_preempt(void);

void sched_enable_preempt_for_cpu(unsigned int cpu);

void sched_disable_preempt_for_cpu(unsigned int cpu);

void sched_block(struct thread *thread);

void __sched_block(struct thread *thread);

void sched_lock(struct thread *thread);

void sched_die();

void scheduler_kill(struct thread *thread);

struct thread *get_thread_for_cpu(unsigned int cpu);

void sched_start_thread_for_cpu(struct thread *thread, unsigned int cpu);

void sched_init_cpu(unsigned int cpu);

void thread_append_to_global_list(struct thread *t);

void thread_remove_from_list(struct thread *t);

struct thread *thread_get_from_tid(int tid);

unsigned long thread_get_addr_limit(void);

void *sched_preempt_thread(void *current_stack);

#define SCHED_NO_CPU_PREFERENCE		(unsigned int) -1

static inline bool sched_needs_resched(struct thread *thread)
{
	return thread->flags & THREAD_NEEDS_RESCHED;
}

static inline void sched_should_resched(void)
{
	struct thread *t = get_current_thread();
	if(t) t->flags |= THREAD_NEEDS_RESCHED;
}

#define set_current_state(state) 			\
do							\
{							\
	struct thread *__t = get_current_thread();	\
	assert(__t != NULL);				\
	__t->status = state;				\
	__sync_synchronize();				\
} while(0);

static inline void thread_get(struct thread *thread)
{
	__atomic_add_fetch(&thread->refcount, 1, __ATOMIC_ACQUIRE);
}

static inline void thread_put(struct thread *thread)
{
	if(__atomic_sub_fetch(&thread->refcount, 1, __ATOMIC_ACQUIRE) == 0)
		thread_destroy(thread);
}

#ifdef __cplusplus
}
#endif

#endif
