/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <onyx/timer.h>
#include <onyx/data_structures.h>
#include <onyx/task_switching.h>
#include <onyx/vmm.h>
#include <onyx/spinlock.h>
#include <onyx/panic.h>
#include <onyx/tss.h>
#include <onyx/process.h>
#include <onyx/idt.h>
#include <onyx/elf.h>
#include <onyx/fpu.h>
#include <onyx/apic.h>
#include <onyx/worker.h>
#include <onyx/cpu.h>

static thread_t **idle_threads;
static spinlock_t wait_queue_lock;
static thread_t *wait_queue;
static bool is_initialized = false;

void sched_append_to_queue(int priority, struct processor *p, 
thread_t *thread);

thread_t *__sched_find_next(struct processor *p)
{
	thread_t *current_thread = get_current_thread();
	if(current_thread)
	{
		if(current_thread->status == THREAD_RUNNABLE)
		{
			/* Re-append the last thread to the queue */
			sched_append_to_queue(current_thread->priority,
			p,
			current_thread);
		}
	}
	/* Go through the different queues, from the highest to lowest */
	for(int i = NUM_PRIO-1; i >= 0; i--)
	{
		/* If this queue has a thread, we found a runnable thread! */
		if(p->thread_queues[i])
		{
			thread_t *ret = p->thread_queues[i];
			/* Advance the queue by one (Don't forget to lock!) */
			acquire_spinlock(&p->queue_locks[i]);
			p->thread_queues[i] = ret->next_prio;
			if(p->thread_queues[i])
				ret->prev_prio = NULL;
			ret->next_prio = NULL;
			release_spinlock(&p->queue_locks[i]);
			return ret;
		}
	}
	return NULL;
}

thread_t *sched_find_next(void)
{
	struct processor *p = get_processor_data();
	return __sched_find_next(p);
}

thread_t *sched_find_runnable(void)
{
	thread_t *thread = sched_find_next();
	if(!thread)
	{
		thread_t *current = get_current_thread();
		if(!current)
			return idle_threads[get_cpu_num()];
		if(current->status == THREAD_RUNNABLE)
			return current;
		return idle_threads[get_cpu_num()];
	}
	return thread;
}

bool sched_is_preemption_disabled(void)
{
	struct processor *p = get_processor_data();
	if(!p)
		return false;
	return p->preemption_disabled;
}
void sched_change_preemption_state(bool disable)
{
	struct processor *p = get_processor_data();
	if(!p)
		return;
	p->preemption_disabled = disable;
}

void *sched_switch_thread(void *last_stack)
{
	if(is_initialized == 0 || sched_is_preemption_disabled())
	{
		return last_stack;
	}
	sched_wake_up_available_threads();
	struct processor *p = get_processor_data();
	thread_t *current_thread = p->current_thread;

	if(unlikely(!current_thread))
	{
		current_thread = sched_find_runnable();
		set_kernel_stack((uintptr_t) current_thread->kernel_stack_top);
		p->kernel_stack = current_thread->kernel_stack_top;
		p->current_thread = current_thread;
		return current_thread->kernel_stack;
	}
	current_thread->kernel_stack = (uintptr_t*) last_stack;
	if(likely(get_current_process()))
	{
		get_current_process()->errno = errno;
	}

	/* Save the FPU state */
	save_fpu(current_thread->fpu_area);

	current_thread = sched_find_runnable();
	p->kernel_stack = current_thread->kernel_stack_top;
	/* Fill the TSS with a kernel stack*/
	set_kernel_stack((uintptr_t) current_thread->kernel_stack_top);
	p->current_thread = current_thread;
	/* Restore the FPU state */
	restore_fpu(current_thread->fpu_area);
	if(get_current_process())
	{
		paging_load_cr3(get_current_process()->cr3);
		errno = get_current_process()->errno;
		wrmsr(FS_BASE_MSR, (uintptr_t) current_thread->fs & 0xFFFFFFFF, (uintptr_t)current_thread->fs >> 32);
		wrmsr(KERNEL_GS_BASE, (uintptr_t) current_thread->gs & 0xFFFFFFFF, (uintptr_t) current_thread->gs >> 32);
	}
	return current_thread->kernel_stack;
}

thread_t *get_current_thread()
{
	struct processor *p = get_processor_data();
	if(unlikely(!p))
		return NULL;
	return (thread_t*) p->current_thread;
}

void sched_idle()
{
	/* This function will not do work at all, just idle using hlt */
	for(;;)
	{
		__asm__ __volatile__("hlt");
	}
}

void sched_append_to_queue(int priority, struct processor *p, 
thread_t *thread)
{
	thread_t *queue = p->thread_queues[priority];
	if(!queue)
	{
		p->thread_queues[priority] = thread;
	}
	else
	{
		while(queue->next_prio) queue = queue->next_prio;
		queue->next_prio = thread;
		thread->prev_prio = queue;
	}
}

int sched_allocate_processor(void)
{
	int nr_cpus = get_nr_cpus();
	int dest_cpu = -1;
	size_t active_threads_min = SIZE_MAX;
	for(int i = 0; i < nr_cpus; i++)
	{
		struct processor *p = get_processor_data_for_cpu(i);
		if(p->active_threads < active_threads_min)
		{
			dest_cpu = i;
			active_threads_min = p->active_threads;
		}
	}
	return dest_cpu;
}

void thread_add(thread_t *thread)
{
	int cpu_num = sched_allocate_processor();
	struct processor *cpu = get_processor_data_for_cpu(cpu_num);
	/* Lock the queue */
	acquire_spinlock(&cpu->queue_locks[thread->priority]);
	thread->cpu = cpu_num;
	cpu->active_threads++;
	/* Append the thread to the queue */
	sched_append_to_queue(thread->priority, cpu, thread);
	/* Unlock the queue */
	release_spinlock(&cpu->queue_locks[thread->priority]);
}

thread_t *sched_create_thread(thread_callback_t callback, uint32_t flags, void* args)
{
	/* Create the thread context (aka the real work) */
	thread_t *t = task_switching_create_context(callback, flags, args);
	if(!t)
		return NULL;
	return t;
}

thread_t* sched_create_main_thread(thread_callback_t callback, uint32_t flags, int argc, char **argv, char **envp)
{
	/* Create the thread context (aka the real work) */
	thread_t *t = task_switching_create_main_progcontext(callback, flags, argc, argv, envp);
	if(!t)
		return NULL;
	return t;
}

extern void _sched_yield();
int sched_init()
{
	idle_threads = malloc(sizeof(void*) * get_nr_cpus());
	assert(idle_threads);
	for(int i = 0; i < get_nr_cpus(); i++)
	{
		idle_threads[i] = task_switching_create_context(sched_idle, 1, NULL);
		assert(idle_threads[i]);
		idle_threads[i]->status = THREAD_IDLE;
	}
	is_initialized = true;
	return 0;
}

void sched_yield()
{
	__asm__ __volatile__("int $0x81");
}

void sched_sleep(unsigned long ms)
{
	thread_t *current = get_current_thread();
	current->timestamp = get_tick_count();
	current->sleeping_for = ms;
	thread_set_state(current, THREAD_BLOCKED);
	sched_yield();
}
int sched_remove_thread_from_execution(thread_t *thread)
{
	int cpu = thread->cpu;
	struct processor *p = get_processor_data_for_cpu(cpu);
	assert(p != NULL);
	acquire_spinlock(&p->queue_locks[thread->priority]);
	for(thread_t *t = p->thread_queues[thread->priority]; t; t = t->next_prio)
	{
		if(t == thread)
		{
			if(t->prev_prio)
				t->prev_prio->next_prio = t->next_prio;
			else
			{
				p->thread_queues[thread->priority] = t->next_prio;
			}
			if(t->next_prio)
				t->next_prio->prev_prio = t->prev_prio;
			t->prev_prio = NULL;
			t->next_prio = NULL;
			release_spinlock(&p->queue_locks[thread->priority]);
			return 0;
		}
	}
	release_spinlock(&p->queue_locks[thread->priority]);
	return -1;
}
static void remove_from_wait_queue(thread_t *thread);
void sched_remove_thread(thread_t *thread)
{
	if(sched_remove_thread_from_execution(thread) < 0)
		remove_from_wait_queue(thread);
	thread_set_state(thread, THREAD_DEAD);
}
void set_current_thread(thread_t *t)
{
	get_processor_data()->current_thread = t;
}
pid_t sys_set_tid_address(pid_t *tidptr)
{
	return get_current_thread()->id;
}
int sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
	struct timespec ts;
	if(copy_from_user(&ts, req, sizeof(struct timespec)) < 0)
		return -EFAULT;
	time_t ticks = ts.tv_sec * 1000;
	if(req->tv_nsec)
	{
		if(ts.tv_nsec < 500)
			ticks++;
	}
	sched_sleep(ticks);
	return 0;
}

extern void thread_finish_destruction(void*);

void thread_destroy(thread_t *thread)
{
	/* This function should destroy everything that we can destroy right now.
	 * We can't destroy things like the kernel stack or the FPU area, because we'll eventually 
	 * need to context switch out of here,
	 * or you know, we're actually using the kernel stack right now!
	*/
	
	/* Remove the thread from the queue */
	sched_remove_thread(thread);

	/* Destroy the user stack */
	if(thread->user_stack_bottom) vmm_destroy_mappings(thread->user_stack_bottom, 256);
	
	/* Schedule further thread destruction */
	struct work_request req;
	req.func = thread_finish_destruction;
	req.param = thread;
	worker_schedule(&req, WORKER_PRIO_NORMAL);
}

static void append_to_wait_queue(thread_t *thread)
{
	acquire_spinlock(&wait_queue_lock);
	if(!wait_queue)
	{
		wait_queue = thread;
		thread->prev_wait = NULL;
		thread->next_wait = NULL;
	}
	else
	{
		thread_t *t = wait_queue;
		while(t->next_wait) t = t->next_wait;
		t->next_wait = thread;
		thread->prev_wait = t;
		thread->next_wait = NULL;
	}
	release_spinlock(&wait_queue_lock);
}
static void remove_from_wait_queue(thread_t *thread)
{
	assert(thread != NULL);

	acquire_spinlock(&wait_queue_lock);
	if(wait_queue == thread)
	{
		wait_queue = wait_queue->next_wait;
		wait_queue->prev_wait = NULL;
		thread->prev_wait = thread->next_wait = NULL;
	}
	else
	{
		for(thread_t *t = wait_queue; t->next; t = t->next)
		{
			if(t->next == thread)
			{
				t->next_wait = thread->next_wait;
				t->next_wait->prev_wait = t;
				thread->prev_wait = thread->next_wait = NULL;
			}
		}
	}
	release_spinlock(&wait_queue_lock);
}
void thread_set_state(thread_t *thread, int state)
{
	assert(thread != NULL);
	if(thread->status == state)
		return;
	if(state == THREAD_BLOCKED)
	{
		DISABLE_INTERRUPTS();
		thread->status = state;
		sched_remove_thread_from_execution(thread);
		append_to_wait_queue(thread);
		ENABLE_INTERRUPTS();
	}
	else if(state == THREAD_RUNNABLE)
	{
		remove_from_wait_queue(thread);
		thread->status = state;
		struct processor *p = get_processor_data_for_cpu(thread->cpu);
		assert(p != NULL);
		sched_append_to_queue(thread->priority, p,
				      thread);
	}
	else
		thread->status = state;
}
void thread_wake_up(thread_t *thread)
{
	thread_set_state(thread, THREAD_RUNNABLE);
}
void sched_sleep_until_wake(void)
{
	thread_set_state(get_current_thread(), THREAD_BLOCKED);
	sched_yield();
}
void thread_wake_up_ftx(thread_t *thread)
{
	thread_wake_up(thread);
	thread->woken_up_by_futex = true;
}
void thread_reset_futex_state(thread_t *thread)
{
	thread->woken_up_by_futex = false;
}
void sched_start_thread(thread_t *thread)
{
	assert(thread != NULL);
	thread_add(thread);
}

void sched_wake_up_available_threads(void)
{
	/* Multiple cpus processing this list is a waste of time.
	 * Also, timer interrupts are more than likely to happen at the same time,
	 * as they're all configured for the same rate.
	*/
	if(try_and_acquire_spinlock(&wait_queue_lock) == 1)
		return;
	for(thread_t *thread = wait_queue; thread; thread = thread->next_wait)
	{
		if(thread->timestamp + thread->sleeping_for <= get_tick_count() && 
			thread->sleeping_for != 0)
		{
			/* Remove it from the queue */
			if(thread->prev_wait)
			{
				thread->prev_wait->next_wait = thread->next_wait;
				if(thread->next_wait)
				{
					thread->next_wait->prev_wait = thread->prev_wait;
				}
			}
			else
			{
				wait_queue = thread->next_wait;
				if(wait_queue) wait_queue->prev_wait = NULL;
			}
			thread->timestamp = 0;
			thread->sleeping_for = 0;
			struct processor *p = get_processor_data_for_cpu(thread->cpu);
			assert(p != NULL);
			sched_append_to_queue(thread->priority, p,
					      thread);
			thread->prev_wait = NULL;
			thread->status = THREAD_RUNNABLE;
		}
	}
	release_spinlock(&wait_queue_lock);
}
